//! Time-based one-time passwords (RFC 6238 over RFC 4226 HOTP).
//!
//! Accepts what services hand out when you enable two-factor authentication: an
//! `otpauth://totp/...` link (usually behind the QR code) or a bare base32 secret.

use core::fmt;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP configuration. The secret is wiped on drop and never printed.
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

const MAX_PERIOD: u64 = 3600;

impl Totp {
    /// Builds a TOTP from raw secret bytes, mainly for tests and imports.
    pub fn new(
        secret: Vec<u8>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
    ) -> Result<Self> {
        if secret.is_empty() {
            return Err(Error::InvalidInput("the TOTP secret is empty"));
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::InvalidInput("TOTP codes must have 6 to 8 digits"));
        }
        if period == 0 || period > MAX_PERIOD {
            return Err(Error::InvalidInput("invalid TOTP period"));
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
            algorithm,
            digits,
            period,
            issuer: None,
            account: None,
        })
    }

    /// Parses an `otpauth://totp/...` link or a bare base32 secret (spaces and case ignored).
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.len() > 4096 {
            return Err(Error::InvalidInput("TOTP input too long"));
        }
        if input
            .get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            Self::parse_uri(input)
        } else {
            Self::new(user_secret(input)?, TotpAlgorithm::Sha1, 6, 30)
        }
    }

    fn parse_uri(uri: &str) -> Result<Self> {
        let rest = &uri["otpauth://".len()..];
        let (kind, rest) = rest
            .split_once('/')
            .ok_or(Error::InvalidInput("malformed otpauth link"))?;
        if !kind.eq_ignore_ascii_case("totp") {
            // HOTP (counter based) needs state we do not keep.
            return Err(Error::InvalidInput(
                "only TOTP (time-based) codes are supported",
            ));
        }
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label)?;

        let mut secret = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        let mut issuer = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value)?;
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(user_secret(&value)?),
                "algorithm" => {
                    algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => TotpAlgorithm::Sha1,
                        "SHA256" => TotpAlgorithm::Sha256,
                        "SHA512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidInput("unsupported TOTP algorithm")),
                    }
                }
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| Error::InvalidInput("invalid TOTP digits"))?
                }
                "period" => {
                    period = value
                        .parse()
                        .map_err(|_| Error::InvalidInput("invalid TOTP period"))?
                }
                "issuer" if !value.is_empty() => issuer = Some(value.to_string()),
                _ => {}
            }
        }

        let mut totp = Self::new(
            secret.ok_or(Error::InvalidInput("the otpauth link has no secret"))?,
            algorithm,
            digits,
            period,
        )?;
        // Label is "Issuer:account" or just "account".
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };
        totp.issuer = issuer.or(label_issuer).filter(|s| !s.is_empty());
        totp.account = Some(account).filter(|s| !s.is_empty());
        Ok(totp)
    }

    /// The code valid at `unix_time` (seconds), zero-padded to [`Self::digits`].
    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = unix_time / self.period;
        let mac = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac::<Hmac<Sha1>>(&self.secret, counter),
            TotpAlgorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.secret, counter),
            TotpAlgorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.secret, counter),
        };
        // Dynamic truncation, RFC 4226 section 5.3.
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        let code = binary % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Seconds until the code valid at `unix_time` changes (1..=period).
    pub fn seconds_remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }
}

fn hmac<M: Mac + hmac::digest::KeyInit>(key: &[u8], counter: u64) -> Zeroizing<Vec<u8>> {
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&counter.to_be_bytes());
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

/// Shortest secret accepted from user input: 80 bits (16 base32 characters), what real
/// services issue. Anything shorter is almost always a word or text pasted by mistake.
const MIN_USER_SECRET_BYTES: usize = 10;

fn user_secret(input: &str) -> Result<Vec<u8>> {
    let secret = base32_decode(input)?;
    if secret.len() < MIN_USER_SECRET_BYTES {
        return Err(Error::InvalidInput("the TOTP secret is too short"));
    }
    Ok(secret)
}

/// RFC 4648 base32, ignoring case, spaces, dashes and `=` padding.
fn base32_decode(input: &str) -> Result<Vec<u8>> {
    // Wiped if a bad character aborts the decoding halfway.
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in input.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            b' ' | b'-' | b'=' | b'\t' => continue,
            _ => return Err(Error::InvalidInput("the TOTP secret is not valid base32")),
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("the TOTP secret is empty"));
    }
    Ok(std::mem::take(&mut *out))
}

/// The decoded value of a query parameter, which may be the secret: wiped on drop.
fn percent_decode(s: &str) -> Result<Zeroizing<String>> {
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s
                    .get(i + 1..i + 3)
                    .ok_or(Error::InvalidInput("malformed otpauth link"))?;
                out.push(
                    u8::from_str_radix(hex, 16)
                        .map_err(|_| Error::InvalidInput("malformed otpauth link"))?,
                );
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Validated in place: `String::from_utf8` would hand the bytes back unwiped on error.
    std::str::from_utf8(&out)
        .map(|t| Zeroizing::new(t.to_owned()))
        .map_err(|_| Error::InvalidInput("malformed otpauth link"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, appendix B: the seeds are ASCII "1234567890" repeated to the hash size.
    fn rfc(algorithm: TotpAlgorithm, len: usize) -> Totp {
        let secret: Vec<u8> = b"1234567890".iter().cycle().take(len).copied().collect();
        Totp::new(secret, algorithm, 8, 30).unwrap()
    }

    #[test]
    fn rfc6238_test_vectors() {
        let cases: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let (sha1, sha256, sha512) = (
            rfc(TotpAlgorithm::Sha1, 20),
            rfc(TotpAlgorithm::Sha256, 32),
            rfc(TotpAlgorithm::Sha512, 64),
        );
        for (t, a, b, c) in cases {
            assert_eq!(sha1.code_at(t), a, "SHA1 t={t}");
            assert_eq!(sha256.code_at(t), b, "SHA256 t={t}");
            assert_eq!(sha512.code_at(t), c, "SHA512 t={t}");
        }
    }

    #[test]
    fn rfc4226_hotp_vectors_through_the_time_step() {
        // HOTP counter c == TOTP at time c*30 with period 30.
        let totp = Totp::new(b"12345678901234567890".to_vec(), TotpAlgorithm::Sha1, 6, 30).unwrap();
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (c, code) in expected.iter().enumerate() {
            assert_eq!(&totp.code_at(c as u64 * 30), code, "counter {c}");
        }
    }

    #[test]
    fn parses_bare_secrets_leniently() {
        let a = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        let b = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(a.code_at(1_793_257_200), b.code_at(1_793_257_200));
        assert_eq!(
            (a.digits, a.period, a.algorithm),
            (6, 30, TotpAlgorithm::Sha1)
        );
        assert_eq!(*a.secret, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn parses_otpauth_links() {
        let t = Totp::parse("otpauth://totp/ACME%20Co:juan@ejemplo.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("juan@ejemplo.com"));
        assert_eq!(
            (t.algorithm, t.digits, t.period),
            (TotpAlgorithm::Sha256, 8, 60)
        );

        let label_only = Totp::parse("otpauth://totp/GitHub:raul?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(label_only.issuer.as_deref(), Some("GitHub"));
        assert_eq!(label_only.account.as_deref(), Some("raul"));
        assert_eq!(label_only.digits, 6);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "   ",
            "not base32!",
            "JBSWY3DP0",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/x",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/%ZZ?secret=JBSWY3DPEHPK3PXP",
            // Valid base32 letters, but a word, not a secret (70 bits).
            "esto-no-es-base32",
            "otpauth://totp/x?secret=ABCDEFGH",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn countdown_and_padding() {
        let t = Totp::new(b"12345678901234567890".to_vec(), TotpAlgorithm::Sha1, 6, 30).unwrap();
        assert_eq!(t.seconds_remaining(0), 30);
        assert_eq!(t.seconds_remaining(29), 1);
        assert_eq!(t.seconds_remaining(30), 30);
        // Leading zeros are kept.
        assert!(t.code_at(1_111_111_109).len() == 6);
    }

    #[test]
    fn debug_hides_the_secret() {
        let t = Totp::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert!(!format!("{t:?}").contains("Hello"));
    }
}
