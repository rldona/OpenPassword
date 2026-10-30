//! The `op-ffi` layer: header parsing and arbitrary `EncryptedItemRecord`s from the app.
#![no_main]
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use op_ffi::{EncryptedItemRecord, Vault};

fn fixed_header() -> String {
    serde_json::to_string(&op_core::fuzzing::header()).expect("header serializes")
}

fn record(item: op_core::EncryptedItem) -> EncryptedItemRecord {
    EncryptedItemRecord {
        id: item.id.iter().map(|b| format!("{b:02x}")).collect(),
        revision: item.revision,
        wrapped_item_key: item.wrapped_item_key,
        overview: item.overview,
        details: item.details,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let key = op_core::fuzzing::TEST_VAULT_KEY.to_vec();
    let Ok(header_json) = String::arbitrary(&mut u) else {
        return;
    };
    // An arbitrary header only has to be parsed; decrypting needs one that is valid.
    let _ = Vault::unlock_with_vault_key(header_json, key.clone());
    let Ok(vault) = Vault::unlock_with_vault_key(fixed_header(), key) else {
        return;
    };
    let record = match u.arbitrary::<bool>() {
        // A validly sealed record whose plaintext is arbitrary: reaches the record conversions.
        Ok(true) => {
            let core_vault = op_core::fuzzing::vault();
            let Ok(item) = op_core::fuzzing::seal_item_part(&core_vault, u.take_rest()) else {
                return;
            };
            record(item)
        }
        _ => {
            let (Ok(id), Ok(revision)) = (String::arbitrary(&mut u), u64::arbitrary(&mut u)) else {
                return;
            };
            let (Ok(wrapped_item_key), Ok(overview), Ok(details)) = (
                Vec::<u8>::arbitrary(&mut u),
                Vec::<u8>::arbitrary(&mut u),
                Vec::<u8>::arbitrary(&mut u),
            ) else {
                return;
            };
            EncryptedItemRecord {
                id,
                revision,
                wrapped_item_key,
                overview,
                details,
            }
        }
    };
    let _ = vault.decrypt_overview(record.clone());
    let _ = vault.decrypt_details(record);
});
