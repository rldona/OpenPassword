//! Decrypting an arbitrary stored item with the fixed test vault: key unwrapping, lengths, AAD.
#![no_main]
use libfuzzer_sys::fuzz_target;
use op_core::EncryptedItem;

fuzz_target!(|data: &[u8]| {
    let Ok(item) = serde_json::from_slice::<EncryptedItem>(data) else {
        return;
    };
    let vault = op_core::fuzzing::vault();
    let _ = vault.decrypt_overview(&item);
    let _ = vault.decrypt_details(&item);
    let _ = vault.decrypt_item(&item);
});
