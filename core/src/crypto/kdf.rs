//! Derivation of the key encryption key from the master password and secret key (spec 5).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use super::keys::{KEY_LEN, Key};
use super::secret_key::SecretKey;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlg {
    Argon2id,
}

/// Argon2id cost parameters. `m_kib` is memory in KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: KdfAlg,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Default for new vaults: 256 MiB, 3 passes, 4 lanes.
    pub const RECOMMENDED: Self = Self::argon2id(262_144, 3, 4);
    /// Lowest cost allowed when creating a vault (low-end devices).
    pub const MINIMUM: Self = Self::argon2id(65_536, 2, 1);
    /// Highest cost accepted from an untrusted header, to prevent denial of service.
    pub const MAXIMUM: Self = Self::argon2id(2_097_152, 16, 16);

    pub const fn argon2id(m_kib: u32, t: u32, p: u32) -> Self {
        Self {
            alg: KdfAlg::Argon2id,
            m_kib,
            t,
            p,
        }
    }

    /// Checks the parameters are usable and not above [`Self::MAXIMUM`].
    /// Applied to every header read from disk.
    pub fn check_bounds(&self) -> Result<()> {
        let max = Self::MAXIMUM;
        if self.m_kib > max.m_kib || self.t > max.t || self.p > max.p {
            return Err(Error::KdfParams("cost above the accepted maximum"));
        }
        self.argon2().map(|_| ())
    }

    /// True if the parameters reach [`Self::MINIMUM`] on every axis.
    pub fn meets_minimum(&self) -> bool {
        let min = Self::MINIMUM;
        self.m_kib >= min.m_kib && self.t >= min.t && self.p >= min.p
    }

    /// Rejects parameters too weak for a new vault.
    pub(crate) fn check_for_new_vault(&self) -> Result<()> {
        self.check_new_vault_policy(cfg!(feature = "insecure-test-params"))
    }

    fn check_new_vault_policy(&self, allow_below_minimum: bool) -> Result<()> {
        self.check_bounds()?;
        if allow_below_minimum || self.meets_minimum() {
            Ok(())
        } else {
            Err(Error::KdfParams("cost below the minimum for new vaults"))
        }
    }

    fn argon2(&self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|_| Error::KdfParams("rejected by Argon2"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// `KEK = HKDF(Argon2id(NFKD(password)) ‖ HKDF(secret_key), salt, "op/kek/v1")`.
pub fn derive_kek(
    password: &str,
    secret_key: &SecretKey,
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<Key> {
    let argon2 = {
        params.check_bounds()?;
        params.argon2()?
    };
    let normalized: Zeroizing<String> = Zeroizing::new(password.nfkd().collect());

    let mut ikm = Zeroizing::new([0u8; 2 * KEY_LEN]);
    let (pw_key, sk_key) = ikm.split_at_mut(KEY_LEN);
    argon2
        .hash_password_into(normalized.as_bytes(), salt, pw_key)
        .map_err(|_| Error::Kdf)?;
    Hkdf::<Sha256>::new(Some(salt), secret_key.expose())
        .expand(b"op/sk/v1", sk_key)
        .map_err(|_| Error::Kdf)?;

    let mut kek = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(salt), ikm.as_slice())
        .expand(b"op/kek/v1", &mut kek)
        .map_err(|_| Error::Kdf)?;
    let key = Key::from_bytes(kek);
    kek.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_vaults_require_the_minimum_cost() {
        assert!(KdfParams::RECOMMENDED.check_new_vault_policy(false).is_ok());
        assert!(KdfParams::MINIMUM.check_new_vault_policy(false).is_ok());
        for weak in [
            KdfParams::argon2id(65_535, 2, 1),
            KdfParams::argon2id(262_144, 1, 4),
            KdfParams::argon2id(256, 1, 1),
        ] {
            assert_eq!(
                weak.check_new_vault_policy(false),
                Err(Error::KdfParams("cost below the minimum for new vaults"))
            );
        }
    }

    #[test]
    fn bounds_reject_costly_or_invalid_params() {
        assert!(KdfParams::MAXIMUM.check_bounds().is_ok());
        assert!(KdfParams::argon2id(2_097_153, 3, 4).check_bounds().is_err());
        assert!(KdfParams::argon2id(262_144, 17, 4).check_bounds().is_err());
        assert!(KdfParams::argon2id(262_144, 0, 4).check_bounds().is_err());
        // Argon2 needs at least 8 KiB per lane.
        assert!(KdfParams::argon2id(16, 1, 4).check_bounds().is_err());
    }
}
