//! Every importer: CSV, Bitwarden JSON, 1Password .1pux (zip) and KDBX. A KeePass file
//! needs its password, so `parse` stops there; `kdbx_fuzzing::file` runs `kdbx::parse`
//! without the key derivation (whose cost the file sets): header, HMAC / start bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = op_core::import::needs_password(data);
    let _ = op_core::import::parse(data, 1_793_257_200);
    op_core::import::kdbx_fuzzing::file(data);
});
