package io.github.rldona.openpassword.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import io.github.rldona.openpassword.core.EncryptedItemRecord

/**
 * Encrypted items. Each row holds only an id, a revision and opaque blobs sealed by op-core:
 * no titles, types or URLs are stored in clear.
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
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

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

    fun upsert(item: EncryptedItemRecord) {
        val values = ContentValues().apply {
            put("id", item.id)
            put("revision", item.revision.toLong())
            put("wrapped_item_key", item.wrappedItemKey)
            put("overview", item.overview)
            put("details", item.details)
        }
        writableDatabase.insertWithOnConflict("items", null, values, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun delete(id: String) {
        writableDatabase.delete("items", "id = ?", arrayOf(id))
    }

    fun clear() {
        writableDatabase.delete("items", null, null)
    }

    private companion object {
        const val NAME = "items.db"
        const val VERSION = 1
    }
}
