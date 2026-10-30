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
import io.github.rldona.openpassword.core.NewImageRecord
import io.github.rldona.openpassword.core.generateSecretKey
import io.github.rldona.openpassword.core.newAttachmentId
import io.github.rldona.openpassword.data.VaultStorage
import io.github.rldona.openpassword.security.BiometricKeyStore
import io.github.rldona.openpassword.session.SessionState
import io.github.rldona.openpassword.session.VaultSession
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ImagesSessionTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val cleanups = mutableListOf<() -> Unit>()

    private class Device(val session: VaultSession, val storage: VaultStorage)

    private fun device(): Device {
        val ns = "test" + UUID.randomUUID().toString().take(8)
        val storage = VaultStorage(context, ns)
        val bio = BiometricKeyStore("$ns-op-biometric-key-v1")
        val session = VaultSession(
            storage,
            context.getSharedPreferences("$ns-security", Context.MODE_PRIVATE),
            KdfProfile.MINIMUM,
            bio,
            bootCount = { 1 },
        )
        cleanups += {
            session.lock()
            storage.destroy(context)
            bio.delete()
            context.deleteSharedPreferences("$ns-security")
        }
        return Device(session, storage)
    }

    @After
    fun cleanup() = cleanups.forEach { it() }

    private fun overview(title: String) =
        ItemOverviewRecord(ItemKindRecord.IDENTITY, title, null, emptyList(), emptyList(), false, 1uL, 1uL)

    /** Structurally valid JPEG with no metadata: SOI, DQT, SOF0, DHT, SOS, EOI. */
    private fun jpeg(seed: Int): ByteArray {
        fun segment(marker: Int, payload: ByteArray): ByteArray {
            val len = payload.size + 2
            return byteArrayOf(0xFF.toByte(), marker.toByte(), (len shr 8).toByte(), len.toByte()) + payload
        }
        return byteArrayOf(0xFF.toByte(), 0xD8.toByte()) +
            segment(0xDB, ByteArray(65) { seed.toByte() }) +
            segment(0xC0, byteArrayOf(8, 0, 1, 0, 1, 1, 1, 0x11, 0)) +
            segment(0xC4, ByteArray(20) { seed.toByte() }) +
            segment(0xDA, byteArrayOf(1, 1, 0, 0, 63, 0)) +
            byteArrayOf(seed.toByte(), (seed + 1).toByte(), 0xFF.toByte(), 0xD9.toByte())
    }

    private fun details(id: String, label: String = "Anverso") =
        ItemDetailsRecord(listOf(FieldRecord(label, FieldKindRecord.IMAGE, id)), "")

    @Test
    fun imageSurvivesLockAndBackupRestore() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val id = newAttachmentId()
        val bytes = jpeg(7)
        val saved = d.session.save(
            null,
            overview("DNI"),
            details(id),
            listOf(NewImageRecord(id, bytes)),
        )

        assertArrayEquals(bytes, d.session.image(saved, id))
        d.session.lock()
        assertEquals(SessionState.Locked, d.session.state.value)
        d.session.unlock(PASSWORD)
        val reopened = (d.session.state.value as SessionState.Unlocked).entries.single()
        assertArrayEquals(bytes, d.session.image(reopened, id))

        val backup = d.session.exportBackup()
        val fresh = device()
        fresh.session.restore(backup, PASSWORD, d.session.secretKey())
        val restored = (fresh.session.state.value as SessionState.Unlocked).entries.single()
        assertArrayEquals(bytes, fresh.session.image(restored, id))
        assertEquals("Anverso", fresh.session.details(restored).fields.single().label)
    }

    @Test
    fun removingAnImageDeletesItsRow() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val id = newAttachmentId()
        val saved = d.session.save(
            null,
            overview("DNI"),
            details(id),
            listOf(NewImageRecord(id, jpeg(3))),
        )
        assertTrue(d.storage.attachmentBytesTotal() > 0)

        val withoutImage = ItemDetailsRecord(emptyList(), "")
        val updated = d.session.save(saved, overview("DNI"), withoutImage)
        assertNull(d.storage.attachment(saved.id, id))
        assertEquals(0L, d.storage.attachmentBytesTotal())
        assertEquals(2uL, updated.record.revision)
        assertNull(d.session.image(updated, id))
    }

    @Test
    fun deletingAnItemDeletesItsImages() = runBlocking {
        val d = device()
        d.session.create(PASSWORD, generateSecretKey())
        val id = newAttachmentId()
        val saved = d.session.save(
            null,
            overview("DNI"),
            details(id),
            listOf(NewImageRecord(id, jpeg(4))),
        )
        d.session.delete(saved)
        assertNull(d.storage.attachment(saved.id, id))
        assertEquals(0L, d.storage.attachmentBytesTotal())
    }

    private companion object {
        const val PASSWORD = "contraseña de prueba larga"
    }
}
