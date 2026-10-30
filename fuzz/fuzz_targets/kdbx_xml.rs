//! The decrypted KeePass XML: entries, groups, recycle bin, history and protected values.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(xml) = std::str::from_utf8(data) {
        op_core::import::kdbx_fuzzing::xml(xml);
    }
});
