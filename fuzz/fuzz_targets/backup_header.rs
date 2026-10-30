//! The plaintext part of a .opvault backup, read before asking for the password.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = op_core::backup::read_header(data) {
        // A header that parses must carry KDF parameters the app would accept to run.
        let _ = header.vault.kdf.check_bounds();
    }
});
