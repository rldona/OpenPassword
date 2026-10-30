//! The serde of the on-disk vault header and items, including `encoding::hex_bytes`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use op_core::{EncryptedItem, VaultHeader};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = serde_json::from_slice::<VaultHeader>(data) {
        // What parses must serialize and parse back to the same value.
        let json = serde_json::to_vec(&header).expect("a parsed header serializes");
        assert_eq!(
            serde_json::from_slice::<VaultHeader>(&json).ok(),
            Some(header)
        );
    }
    if let Ok(item) = serde_json::from_slice::<EncryptedItem>(data) {
        let json = serde_json::to_vec(&item).expect("a parsed item serializes");
        assert_eq!(
            serde_json::from_slice::<EncryptedItem>(&json).ok(),
            Some(item)
        );
    }
});
