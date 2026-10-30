package io.github.rldona.openpassword

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.rldona.openpassword.core.EncryptedAttachmentRecord
import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.data.ItemDatabase
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ItemDatabaseMigrationTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val names = mutableListOf<String>()

    @After
    fun cleanup() {
        names.forEach(context::deleteDatabase)
    }

    private fun name(): String = "test" + UUID.randomUUID().toString().take(8) + "-items.db".also(names::add)

    @Test
    fun aVersionOneDatabaseKeepsItsItemsAndGainsTheAttachmentsTable() {
        val dbName = name()
        context.openOrCreateDatabase(dbName, Context.MODE_PRIVATE, null).use { db ->
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
            db.execSQL(
                "INSERT INTO items VALUES ('00112233445566778899aabbccddeeff', 3, X'01', X'02', X'03')",
            )
            db.version = 1
        }

        ItemDatabase(context, dbName).use { helper ->
            val items = helper.all()
            assertEquals(1, items.size)
            assertEquals(3uL, items.single().revision)
            val tables = helper.readableDatabase.rawQuery(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'attachments'",
                null,
            ).use { it.moveToFirst() }
            assertTrue(tables)
        }
    }

    @Test
    fun readsAndDeletesARowAtTheImageSizeLimit() {
        val dbName = name()
        ItemDatabase(context, dbName).use { db ->
            val item = EncryptedItemRecord(
                id = "00112233445566778899aabbccddeeff",
                revision = 1uL,
                wrappedItemKey = byteArrayOf(1),
                overview = byteArrayOf(2),
                details = byteArrayOf(3),
            )
            val data = ByteArray(1_576_960) { (it % 251).toByte() }
            val attachment = EncryptedAttachmentRecord(item.id, "ffeeddccbbaa99887766554433221100", data)
            db.applyChange(item, listOf(attachment), emptyList())

            assertEquals(attachment.data.size.toLong(), db.attachmentBytesTotal())
            assertArrayEquals(data, db.attachment(item.id, attachment.id)!!.data)

            db.applyChange(item, emptyList(), listOf(attachment.id))
            assertEquals(0L, db.attachmentBytesTotal())
        }
    }
}
