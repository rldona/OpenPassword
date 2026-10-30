//! `SecretString`: a text secret that Rust wipes when it is dropped.
//!
//! Kotlin sees a plain `String` (`uniffi::custom_type!` with `String` as the builtin type), so
//! the generated bindings do not change. What it buys is on the Rust side: UniFFI builds the
//! incoming `String` from the argument buffer without copying it, and this type wipes it when
//! the exported function returns, whatever path it takes. A new function cannot forget the wipe.
//!
//! Accepted leftovers, which Rust cannot reach (docs/threat-model.md, residual risks):
//! - the `String`s of the JVM and Compose, which are immutable and cannot be wiped;
//! - the outgoing `RustBuffer` that UniFFI frees without wiping, and the `String` Rust hands
//!   over to build it (`lower` copies the text, `secret` is wiped on return, and UniFFI frees the copy).

use std::fmt;

use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self(Zeroizing::new(s.to_owned()))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

uniffi::custom_type!(SecretString, String, {
    lower: |secret| secret.expose().to_owned(),
    try_lift: |text| Ok(SecretString::from(text)),
});

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use super::*;

    #[test]
    fn debug_hides_the_value() {
        let secret = SecretString::from("hunter2");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{:?}", Some(secret)).contains("hunter2"));
    }

    #[test]
    fn zeroize_empties_the_text() {
        let mut secret = SecretString::from("hunter2");
        assert_eq!(secret.expose(), "hunter2");
        secret.0.zeroize();
        assert_eq!(secret.expose(), "");
    }
}
