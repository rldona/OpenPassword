//! Length-hiding padding before sealing (spec 6.3).

use zeroize::Zeroizing;

use crate::{Error, Result};

const BLOCK: usize = 64;
const LEN_PREFIX: usize = 4;

/// `u32_le(len) ‖ data ‖ zeros`, up to a multiple of 64 bytes.
pub(crate) fn pad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(data.len()).map_err(|_| Error::InvalidInput("item too large"))?;
    let padded_len = (LEN_PREFIX + data.len()).div_ceil(BLOCK) * BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(padded_len, 0);
    Ok(out)
}

pub(crate) fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.is_empty() || padded.len() % BLOCK != 0 {
        return Err(Error::Malformed("padding length"));
    }
    let (prefix, rest) = padded.split_at(LEN_PREFIX);
    let len = u32::from_le_bytes(prefix.try_into().expect("prefix is 4 bytes")) as usize;
    if len > rest.len() || rest[len..].iter().any(|&b| b != 0) {
        return Err(Error::Malformed("padding content"));
    }
    Ok(&rest[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_block_multiple() {
        for len in [0, 1, 59, 60, 61, 124, 1000] {
            let data = vec![0xAB; len];
            let padded = pad(&data).unwrap();
            assert_eq!(padded.len() % BLOCK, 0);
            assert_eq!(unpad(&padded).unwrap(), data.as_slice());
        }
        assert_eq!(pad(&[0; 60]).unwrap().len(), 64);
        assert_eq!(pad(&[0; 61]).unwrap().len(), 128);
    }

    #[test]
    fn rejects_bad_padding() {
        let mut padded = pad(b"hola").unwrap();
        padded[20] = 1;
        assert!(unpad(&padded).is_err());
        assert!(unpad(&[0; 63]).is_err());
        let mut too_long = vec![0u8; 64];
        too_long[0] = 61;
        assert!(unpad(&too_long).is_err());
    }
}
