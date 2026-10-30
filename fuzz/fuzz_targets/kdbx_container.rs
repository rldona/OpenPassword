//! KDBX behind the key derivation: the header checks, block framing, outer cipher, gunzip,
//! inner header and XML, with a file sealed under a fixed key. The first byte picks the shape.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    op_core::import::kdbx_fuzzing::container(data);
});
