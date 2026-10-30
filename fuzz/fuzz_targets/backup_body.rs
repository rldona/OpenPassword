//! The body of a backup after the STREAM cipher: chunking and the JSON of the items. No KDF.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let vault = op_core::fuzzing::vault();
    let backup = op_core::fuzzing::seal_backup(&vault, data);
    let _ = op_core::fuzzing::open_with_vault(&backup, &vault);
    // Also the raw bytes, which stop at the header or the first chunk.
    let _ = op_core::fuzzing::open_with_vault(data, &vault);
});
