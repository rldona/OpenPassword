package io.github.rldona.openpassword

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rldona.openpassword.core.FieldKindRecord
import io.github.rldona.openpassword.core.FieldRecord
import io.github.rldona.openpassword.core.ItemDetailsRecord
import io.github.rldona.openpassword.core.ItemKindRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.KdfProfile
import io.github.rldona.openpassword.core.OpException
import io.github.rldona.openpassword.core.generateSecretKey
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.security.BiometricKeyStore
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.session.UnlockResult
import io.github.rldona.openpassword.session.VaultEntry
import io.github.rldona.openpassword.session.VaultSession
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/**
 * The whole session against the real op-core library, Android Keystore and SQLite.
 * Every test uses its own namespace and deletes it afterwards: app data is never touched.
 */
@RunWith(AndroidJUnit4::class)
class VaultSessionTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val cleanups = mutableListOf<() -> Unit>()

    private class Device(val ns: String, val session: VaultSession, val storage: VaultStorage, var boots: Int)

    private fun device(): Device {
        val ns = "test" + UUID.randomUUID().toString().take(8)
        val storage = VaultStorage(context, ns)
        val prefs = context.getSharedPreferences("$ns-security", Context.MODE_PRIVATE)
        val bio = BiometricKeyStore("$ns-op-biometric-key-v1")
        lateinit var d: Device
        // MINIMUM keeps each Argon2id run around 50 ms on a phone.
        val session = VaultSession(storage, prefs, KdfProfile.MINIMUM, bio, bootCount = { d.boots })
        d = Device(ns, session, storage, boots = 1)
        cleanups += {
            session.lock()
            storage.destroy(context)
            bio.delete()
            context.deleteSharedPreferences("$ns-security")
        }
        return d
    }

    @After
    fun cleanup() = cleanups.forEach { it() }

    private fun overview(title: String, kind: ItemKindRecord = ItemKindRecord.PIN) =
        ItemOverviewRecord(kind, title, null, emptyList(), emptyList(), false, 1uL, 1uL)

    private fun details(value: String) = ItemDetailsRecord(listOf(FieldRecord("Código", FieldKindRecord.PIN, value)), "")

    private fun entries(s: VaultSession) = (s.state.value as SessionState.Unlocked).entries

    private fun titles(s: VaultSession) = entries(s).map { it.overview.title }.sorted()

    @Test
    fun createLockAndUnlock() = runBlocking {
        val d = device()
        assertEquals(SessionState.NoVault, d.session.state.value)
        d.session.create(PASSWORD, generateSecretKey())
        assertTrue(d.session.state.value is SessionState.Unlocked)
        d.session.lock()
        assertEquals(SessionState.Locked, d.session.state.value)
        assertEquals(UnlockResult.Success, d.session.unlock(PASSWORD))
    }

    @Test
    fun wrongPasswordsTriggerTheWait() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        d.session.lock()
        repeat(3) { assertEquals(UnlockResult.WrongPassword(0), d.session.unlock("mala")) }
        val fourth = d.session.unlock("mala") as UnlockResult.WrongPassword
        assertTrue("4th: ${fourth.waitSeconds}", fourth.waitSeconds in 29..30)
        // Even the right password must wait now.
        assertTrue(d.session.unlock(PASSWORD) is UnlockResult.MustWait)
        assertEquals(SessionState.Locked, d.session.state.value)
    }

    @Test
    fun itemsRoundTripAndKeepRevisions() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val saved = d.session.save(null, overview("Alarma"), details("2958"))
        assertEquals(1uL, saved.record.revision)
        val edited = d.session.save(saved, overview("Alarma casa"), details("1111"))
        assertEquals(saved.id, edited.id)
        assertEquals(2uL, edited.record.revision)
        assertEquals("1111", d.session.details(edited).fields.single().value)

        d.session.lock()
        d.session.unlock(PASSWORD)
        val reopened = entries(d.session).single()
        assertEquals("Alarma casa", reopened.overview.title)
        assertEquals("1111", d.session.details(reopened).fields.single().value)

        d.session.delete(reopened)
        assertTrue(entries(d.session).isEmpty())
        assertTrue(d.storage.items().isEmpty())
    }

    @Test
    fun nothingIsStoredInClear() = runBlocking {
        val d = device()
        val sk = generateSecretKey()
        d.session.create(PASSWORD, sk)
        d.session.save(null, overview("Visa BBVA", ItemKindRecord.CARD), details("4940192355674821"))
        val files = context.noBackupFilesDir.listFiles()!!.filter { it.name.startsWith(d.ns) } +
            File(context.getDatabasePath("${d.ns}-items.db").path)
        assertTrue(files.size >= 3)
        val needles = listOf(sk, sk.substring(4, 10), PASSWORD, "Visa BBVA", "4940192355674821", "card")
        for (file in files) {
            val text = String(file.readBytes(), Charsets.ISO_8859_1)
            for (n in needles) assertFalse("'$n' in the clear in ${file.name}", text.contains(n))
        }
    }

    @Test
    fun exportAndRestoreOnANewDevice() = runBlocking {
        val old = device()
        val sk = generateSecretKey()
        old.session.create(PASSWORD, sk)
        old.session.save(null, overview("Uno"), details("1"))
        old.session.save(null, overview("Dos"), details("2"))
        val backup = old.session.exportBackup()

        val new = device()
        // Lowercase and spaces instead of dashes, as someone might type it from paper.
        new.session.restore(backup, PASSWORD, sk.lowercase().replace('-', ' '))
        assertEquals(listOf("Dos", "Uno"), titles(new.session))
        new.session.lock()
        assertEquals(UnlockResult.Success, new.session.unlock(PASSWORD))
        assertEquals("2", new.session.details(entries(new.session).first { it.overview.title == "Dos" }).fields.single().value)
    }

    @Test
    fun failedRestoreLeavesNoVaultBehind() = runBlocking {
        val old = device()
        old.session.create(PASSWORD, generateSecretKey())
        old.session.save(null, overview("Uno"), details("1"))
        val backup = old.session.exportBackup()

        val new = device()
        try {
            new.session.restore(backup, PASSWORD, generateSecretKey())
            fail("a foreign secret key must not open the backup")
        } catch (_: OpException.WrongSecretKey) {
        }
        assertFalse(new.storage.hasVault())
        assertTrue(new.storage.items().isEmpty())
        assertEquals(SessionState.NoVault, new.session.state.value)
    }

    @Test
    fun importingAnOlderCopyOfTheSameVaultKeepsNewerItems() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val a = d.session.save(null, overview("A"), details("1"))
        val backup = d.session.exportBackup()
        d.session.save(a, overview("A editada"), details("2"))
        d.session.save(null, overview("B"), details("3"))

        val summary = d.session.importBackup(backup, PASSWORD, secretKey = null)
        assertEquals(0, summary.added)
        assertEquals(0, summary.updated)
        assertEquals(1, summary.unchanged)
        assertEquals(listOf("A editada", "B"), titles(d.session))
    }

    @Test
    fun importingANewerCopyUpdatesAndAddsItems() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val a = d.session.save(null, overview("A"), details("1"))
        val older = d.session.exportBackup()
        d.session.save(a, overview("A editada"), details("2"))
        d.session.save(null, overview("B"), details("3"))
        val newer = d.session.exportBackup()

        val other = device()
        val sk = d.session.secretKey()
        other.session.restore(older, PASSWORD, sk)
        val summary = other.session.importBackup(newer, PASSWORD, sk)
        assertEquals(1, summary.added)
        assertEquals(1, summary.updated)
        assertEquals(listOf("A editada", "B"), titles(other.session))
    }

    @Test
    fun importingAnotherVaultReencryptsItsItems() = runBlocking {
        val mine = device()
        mine.session.create(PASSWORD, generateSecretKey())
        mine.session.save(null, overview("Mío"), details("1"))

        val theirs = device()
        val theirKey = generateSecretKey()
        theirs.session.create("otra contraseña larga", theirKey)
        theirs.session.save(null, overview("Suyo"), details("42"))
        val foreign = theirs.session.exportBackup()

        val summary = mine.session.importBackup(foreign, "otra contraseña larga", theirKey)
        assertEquals(1, summary.added)
        assertEquals(listOf("Mío", "Suyo"), titles(mine.session))
        // After a fresh unlock the imported item opens with this vault's keys alone.
        mine.session.lock()
        mine.session.unlock(PASSWORD)
        val suyo: VaultEntry = entries(mine.session).first { it.overview.title == "Suyo" }
        assertEquals("42", mine.session.details(suyo).fields.single().value)
    }

    @Test
    fun locksInTheBackgroundWithoutComingBack() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        InstrumentationRegistry.getInstrumentation().runOnMainSync { d.session.onAppBackgrounded() }
        kotlinx.coroutines.delay(VaultSession.BACKGROUND_TIMEOUT_MS - 5_000)
        assertTrue("still open before 30 s", d.session.state.value is SessionState.Unlocked)
        kotlinx.coroutines.delay(7_000)
        // No onAppForegrounded(): autofill must not keep offering logins from a forgotten session.
        assertEquals(SessionState.Locked, d.session.state.value)
    }

    @Test
    fun biometricUnlockGivesWayToThePasswordAfterRebootOrInvalidation() {
        val d = device()
        runBlocking { d.session.create(PASSWORD, generateSecretKey()) }
        assertNull(d.session.passwordRequiredReason())
        // Pretend biometric unlock is on (the real key needs a fingerprint).
        d.storage.writeBiometricVaultKey(byteArrayOf(1) + ByteArray(12) + ByteArray(48))
        assertTrue(d.session.canUseBiometricNow())

        d.boots++
        assertTrue(d.session.passwordRequiredReason()!!.contains("reiniciado"))
        assertFalse(d.session.canUseBiometricNow())

        // No Keystore key behind the file (as after enrolling a new fingerprint): turned off.
        assertNull(d.session.biometricUnlockCipher())
        assertFalse(d.session.isBiometricEnabled())
    }

    companion object {
        const val PASSWORD = "contraseña de prueba larga"
    }
}
