use crate::{Error, Result};

/// Fills `buf` from the operating system CSPRNG.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}
