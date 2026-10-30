package io.github.rldona.openpassword.backup

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.provider.DocumentsContract
import io.github.rldona.openpassword.core.InternalException
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.session.VaultSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDateTime

/**
 * Writes encrypted `.opvault` backups to a folder the user picked (Storage Access
 * Framework). The app itself never touches the network: if the folder belongs to a cloud
 * or Syncthing app, that app syncs it.
 *
 * Backups need the vault key, so they only happen while the vault is unlocked: a few
 * seconds after each change, and on unlock when the last one is older than a day.
 * Changes made right before locking are backed up on the next unlock.
 */
class AutoBackup(
    private val context: Context,
    private val session: VaultSession,
    private val prefs: SharedPreferences,
    private val scope: CoroutineScope,
) {
    data class Status(
        val folder: Uri? = null,
        val folderName: String? = null,
        val lastBackupAt: Long? = null,
        val lastError: String? = null,
        val pending: Boolean = false,
    ) {
        val enabled: Boolean get() = folder != null
    }

    private val _status = MutableStateFlow(load())
    val status: StateFlow<Status> = _status.asStateFlow()
    private var scheduled: Job? = null

    /** Uses [tree] from ACTION_OPEN_DOCUMENT_TREE and makes a first backup right away. */
    fun setFolder(tree: Uri, displayName: String?) {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        context.contentResolver.takePersistableUriPermission(tree, flags)
        _status.value.folder?.takeIf { it != tree }?.let(::release)
        prefs.edit().putString(KEY_FOLDER, tree.toString()).putString(KEY_FOLDER_NAME, displayName).remove(KEY_ERROR).apply()
        markPending()
        publish()
        schedule(0)
    }

    fun disable() {
        _status.value.folder?.let(::release)
        prefs.edit().remove(KEY_FOLDER).remove(KEY_FOLDER_NAME).remove(KEY_ERROR).remove(KEY_PENDING).apply()
        scheduled?.cancel()
        publish()
    }

    fun onVaultChanged() {
        if (!_status.value.enabled) return
        markPending()
        schedule(DEBOUNCE_MS)
    }

    fun onUnlocked() {
        val s = _status.value
        if (!s.enabled) return
        val stale = System.currentTimeMillis() - (s.lastBackupAt ?: 0) >= DAY_MS
        if (s.pending || stale) schedule(0)
    }

    /** Backs up now. Returns null on success or the message to show. */
    suspend fun backupNow(): String? {
        scheduled?.cancel()
        return runBackup()
    }

    private fun schedule(delayMs: Long) {
        scheduled?.cancel()
        scheduled = scope.launch {
            delay(delayMs)
            runBackup()
        }
    }

    private suspend fun runBackup(): String? {
        val tree = _status.value.folder ?: return "La copia automática está desactivada."
        val bytes = try {
            session.exportBackup()
        } catch (_: OpException.Locked) {
            // Stays pending: done on the next unlock.
            return "El baúl está bloqueado: la copia se hará al desbloquear."
        } catch (e: OpException) {
            return fail("No se pudo cifrar la copia.")
        } catch (_: InternalException) {
            return fail("No se pudo cifrar la copia.")
        }
        return try {
            withContext(Dispatchers.IO) { write(tree, bytes) }
            prefs.edit()
                .putLong(KEY_LAST, System.currentTimeMillis())
                .putBoolean(KEY_PENDING, false)
                .remove(KEY_ERROR)
                .apply()
            publish()
            null
        } catch (_: SecurityException) {
            fail("OpenPassword ya no tiene permiso para usar esa carpeta. Elígela de nuevo.")
        } catch (e: CancellationException) {
            // Cancelled by disable() or a newer schedule: not a write error, so no message is stored.
            throw e
        } catch (_: Exception) {
            fail("No se pudo escribir en la carpeta. ¿Sigue existiendo?")
        }
    }

    private fun write(tree: Uri, bytes: ByteArray) {
        val resolver = context.contentResolver
        val parentId = DocumentsContract.getTreeDocumentId(tree)
        val parent = DocumentsContract.buildDocumentUriUsingTree(tree, parentId)
        val name = BackupNames.nameFor(LocalDateTime.now())
        val doc = DocumentsContract.createDocument(resolver, parent, "application/octet-stream", name)
            ?: error("createDocument returned null")
        resolver.openOutputStream(doc, "wt")?.use { it.write(bytes) } ?: error("cannot open $doc")

        // Rotation: list the folder, delete only our own older backups.
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId)
        val existing = mutableMapOf<String, String>() // name -> document id
        resolver.query(
            children,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null, null, null,
        )?.use { c ->
            while (c.moveToNext()) existing[c.getString(1)] = c.getString(0)
        }
        BackupNames.toDelete(existing.keys.toList(), KEEP).forEach { old ->
            existing[old]?.let { id -> DocumentsContract.deleteDocument(resolver, DocumentsContract.buildDocumentUriUsingTree(tree, id)) }
        }
    }

    private fun fail(message: String): String {
        prefs.edit().putString(KEY_ERROR, message).apply()
        publish()
        return message
    }

    private fun markPending() = prefs.edit().putBoolean(KEY_PENDING, true).apply()

    private fun release(tree: Uri) {
        runCatching {
            context.contentResolver.releasePersistableUriPermission(
                tree,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
    }

    private fun publish() {
        _status.value = load()
    }

    private fun load() = Status(
        folder = prefs.getString(KEY_FOLDER, null)?.let(Uri::parse),
        folderName = prefs.getString(KEY_FOLDER_NAME, null),
        lastBackupAt = prefs.getLong(KEY_LAST, 0).takeIf { it > 0 },
        lastError = prefs.getString(KEY_ERROR, null),
        pending = prefs.getBoolean(KEY_PENDING, false),
    )

    companion object {
        const val KEEP = 10
        const val DEBOUNCE_MS = 5_000L
        private const val DAY_MS = 24L * 3600 * 1000
        private const val KEY_FOLDER = "auto_backup_folder"
        private const val KEY_FOLDER_NAME = "auto_backup_folder_name"
        private const val KEY_LAST = "auto_backup_last"
        private const val KEY_ERROR = "auto_backup_error"
        private const val KEY_PENDING = "auto_backup_pending"
    }
}
