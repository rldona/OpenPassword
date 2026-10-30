package io.github.rldona.openpassword.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import io.github.rldona.openpassword.core.EncryptedAttachmentRecord
import io.github.rldona.openpassword.core.EncryptedItemRecord

/**
 * Encrypted items and their sealed images. Each row holds only ids and opaque blobs sealed by
 * op-core: no titles, types, URLs or image bytes in clear.
 *
 * Images live in their own table, one row each: an item's details row would otherwise approach
 * SQLite's 2 MB `CursorWindow` limit as soon as it carried two photos. There is no foreign key
 * on purpose: `CONFLICT_REPLACE` would delete and reinsert the item row on every edit, and a
 * cascade would take its images with it.
 */
class ItemDatabase(context: Context, name: String = NAME) : SQLiteOpenHelper(context, name, null, VERSION) {

    override fun onConfigure(db: SQLiteDatabase) {
        // Overwrite deleted content instead of leaving it in free pages.
        // rawQuery, not execSQL: this PRAGMA returns a row, which execSQL rejects.
        db.rawQuery("PRAGMA secure_delete = ON", null).use { it.moveToFirst() }
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE items (
                id TEXT PRIMARY KEY NOT NULL,
                revision INTEGER NOT NULL,
                wrapped_item_key BLOB NOT NULL,
                overview BLOB NOT NULL,
                details BLOB NOT NULL
            )
            """.trimIndent(),
        )
        createAttachments(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) createAttachments(db)
    }

    private fun createAttachments(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE attachments (
                item_id TEXT NOT NULL,
                id TEXT NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (item_id, id)
            )
            """.trimIndent(),
        )
    }

    fun all(): List<EncryptedItemRecord> =
        readableDatabase.query("items", null, null, null, null, null, null).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        EncryptedItemRecord(
                            id = c.getString(0),
                            revision = c.getLong(1).toULong(),
                            wrappedItemKey = c.getBlob(2),
                            overview = c.getBlob(3),
                            details = c.getBlob(4),
                        ),
                    )
                }
            }
        }

    fun allAttachments(): List<EncryptedAttachmentRecord> =
        readableDatabase.query("attachments", null, null, null, null, null, null).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        EncryptedAttachmentRecord(
                            itemId = c.getString(0),
                            id = c.getString(1),
                            data = c.getBlob(2),
                        ),
                    )
                }
            }
        }

    /** One image, without reading the rest of the item's images. */
    fun attachment(itemId: String, id: String): EncryptedAttachmentRecord? =
        readableDatabase.query(
            "attachments",
            arrayOf("item_id", "id", "data"),
            "item_id = ? AND id = ?",
            arrayOf(itemId, id),
            null,
            null,
            null,
        ).use { c ->
            if (!c.moveToFirst()) return null
            EncryptedAttachmentRecord(c.getString(0), c.getString(1), c.getBlob(2))
        }

    fun attachmentSize(itemId: String, id: String): Long =
        readableDatabase.rawQuery(
            "SELECT length(data) FROM attachments WHERE item_id = ? AND id = ?",
            arrayOf(itemId, id),
        ).use { c -> if (c.moveToFirst()) c.getLong(0) else 0 }

    fun attachmentBytesTotal(): Long =
        readableDatabase.rawQuery("SELECT COALESCE(SUM(length(data)), 0) FROM attachments", null).use { c ->
            if (c.moveToFirst()) c.getLong(0) else 0
        }

    fun upsert(item: EncryptedItemRecord) {
        putItem(writableDatabase, item)
    }

    /**
     * Writes an item and its new images, and deletes the removed ones, in one transaction.
     * Removing a row from free pages needs `secure_delete`, already on.
     */
    fun applyChange(item: EncryptedItemRecord, added: List<EncryptedAttachmentRecord>, removed: List<String>) {
        transaction { db ->
            putItem(db, item)
            added.forEach { putAttachment(db, it, SQLiteDatabase.CONFLICT_ABORT) }
            removed.forEach { deleteAttachment(db, item.id, it) }
        }
        checkpointIfRemoved(removed.isNotEmpty())
    }

    fun deleteItem(id: String) {
        transaction { db ->
            db.delete("items", "id = ?", arrayOf(id))
            db.delete("attachments", "item_id = ?", arrayOf(id))
        }
        checkpointIfRemoved(true)
    }

    /** Replaces the whole vault, for a restore. Clears both tables first. */
    fun replaceAll(items: List<EncryptedItemRecord>, attachments: List<EncryptedAttachmentRecord>) {
        transaction { db ->
            db.delete("items", null, null)
            db.delete("attachments", null, null)
            items.forEach { putItem(db, it) }
            attachments.forEach { putAttachment(db, it, SQLiteDatabase.CONFLICT_ABORT) }
            db.delete("attachments", "item_id NOT IN (SELECT id FROM items)", null)
        }
        checkpointIfRemoved(true)
    }

    /**
     * One transaction for an import: items to create or replace, images to add if missing, and
     * images to delete. Never deletes an item.
     */
    fun applyImport(
        items: List<EncryptedItemRecord>,
        insertions: List<EncryptedAttachmentRecord>,
        deletions: List<Pair<String, String>>,
    ) {
        transaction { db ->
            items.forEach { putItem(db, it) }
            insertions.forEach { putAttachment(db, it, SQLiteDatabase.CONFLICT_IGNORE) }
            deletions.forEach { (itemId, id) -> deleteAttachment(db, itemId, id) }
        }
        checkpointIfRemoved(deletions.isNotEmpty())
    }

    /** Drops images whose item is gone, e.g. after an interrupted restore. */
    fun sweepOrphans() {
        writableDatabase.delete("attachments", "item_id NOT IN (SELECT id FROM items)", null)
    }

    fun clear() {
        transaction { db ->
            db.delete("items", null, null)
            db.delete("attachments", null, null)
        }
        checkpointIfRemoved(true)
    }

    private fun putItem(db: SQLiteDatabase, item: EncryptedItemRecord) {
        val values = ContentValues().apply {
            put("id", item.id)
            put("revision", item.revision.toLong())
            put("wrapped_item_key", item.wrappedItemKey)
            put("overview", item.overview)
            put("details", item.details)
        }
        db.insertWithOnConflict("items", null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    private fun putAttachment(db: SQLiteDatabase, attachment: EncryptedAttachmentRecord, conflict: Int) {
        val values = ContentValues().apply {
            put("item_id", attachment.itemId)
            put("id", attachment.id)
            put("data", attachment.data)
        }
        db.insertWithOnConflict("attachments", null, values, conflict)
    }

    private fun deleteAttachment(db: SQLiteDatabase, itemId: String, id: String) {
        db.delete("attachments", "item_id = ? AND id = ?", arrayOf(itemId, id))
    }

    private inline fun transaction(block: (SQLiteDatabase) -> Unit) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            block(db)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    /** Moves the WAL past the deleted ciphertext instead of leaving it there until the next checkpoint. */
    private fun checkpointIfRemoved(removed: Boolean) {
        if (!removed) return
        runCatching {
            writableDatabase.rawQuery("PRAGMA wal_checkpoint(TRUNCATE)", null).use { it.moveToFirst() }
        }
    }

    private companion object {
        const val NAME = "items.db"
        const val VERSION = 2
    }
}
