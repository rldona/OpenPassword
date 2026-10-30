package io.github.rldona.openpassword.session

import io.github.rldona.openpassword.core.EncryptedItemRecord
import io.github.rldona.openpassword.core.ItemOverviewRecord
import io.github.rldona.openpassword.core.OpException

/** The items that could be read, and the ids of the rows that could not (ID-INT-06). */
data class LoadedEntries(val entries: List<VaultEntry>, val unreadable: List<String>)

/**
 * Policy: a row whose overview does not decrypt ([OpException.Corrupted]) is left out of the
 * list and reported, instead of making the whole vault impossible to open. The row itself is
 * never touched here: it stays in storage, goes into every backup, and may be repaired by
 * importing a good copy of the same vault. Any other failure (locked, internal panic) still
 * aborts the load, because it says something about the vault, not about one row.
 */
internal fun loadEntries(
    records: List<EncryptedItemRecord>,
    overview: (EncryptedItemRecord) -> ItemOverviewRecord,
): LoadedEntries {
    val entries = mutableListOf<VaultEntry>()
    val unreadable = mutableListOf<String>()
    for (record in records) {
        try {
            entries += VaultEntry(record, overview(record))
        } catch (_: OpException.Corrupted) {
            unreadable += record.id
        }
    }
    return LoadedEntries(entries, unreadable)
}
