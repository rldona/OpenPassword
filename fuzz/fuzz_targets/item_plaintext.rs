//! What comes after the AEAD of an item: `padding::unpad` and the JSON of overview and details.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let vault = op_core::fuzzing::vault();
    let item = op_core::fuzzing::seal_item_part(&vault, data).expect("sealing cannot fail");
    let _ = vault.decrypt_details(&item);
    let _ = vault.decrypt_overview(&item);
});
