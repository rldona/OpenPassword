//! The JPEG validator that guards every new image: it must accept and reject without
//! panicking, and never read past the input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = op_core::fuzzing::check_jpeg(data);
});
