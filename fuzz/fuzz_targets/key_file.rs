//! KeePass key files: XML v1/v2, 32 raw bytes, 64 hex digits or anything else (hashed).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| op_core::import::kdbx_fuzzing::key_file(data));
