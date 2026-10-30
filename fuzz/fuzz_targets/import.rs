//! Every importer up to the KDF: CSV, Bitwarden JSON, 1Password .1pux (zip) and the KDBX
//! outer header. Files that need a password stop before the key derivation.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = op_core::import::needs_password(data);
    let _ = op_core::import::parse(data, 1_793_257_200);
});
