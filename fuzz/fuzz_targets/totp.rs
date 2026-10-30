//! otpauth:// links and bare secrets, as pasted by the user or read from a QR code.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(totp) = op_core::totp::Totp::parse(input) {
            let _ = totp.code_at(u64::MAX);
            let _ = totp.seconds_remaining(u64::MAX);
        }
    }
});
