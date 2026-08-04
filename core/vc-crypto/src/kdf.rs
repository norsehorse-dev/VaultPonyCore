//! Header-key derivation: PBKDF2-HMAC over the candidate PRF (doc §6).

use pbkdf2::pbkdf2_hmac;
use vc_types::{VcError, VcResult};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Derived header-key material: sized for the largest cascade
/// (3 layers x 64 bytes = 192). Only the first `len` bytes are meaningful —
/// deriving exactly what the scheme needs matters, because every extra
/// PBKDF2 output block costs the full iteration count again. Zeroized on
/// drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HeaderKey {
    bytes: [u8; 192],
    #[zeroize(skip)]
    len: usize,
}

impl HeaderKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// PBKDF2 with the given PRF over (passphrase, 64-byte salt, iterations),
/// producing `key_len` bytes (the scheme's `key_bytes()`).
///
/// Iterations come from `vc_types::registry::iterations_for_pim`. Keyfile
/// pool mixing (P10) slots in ahead of this call, not inside it.
///
/// P0 status: SHA-512 is fixture-verified. The other four are wired per the
/// upstream Pkcs5.c mapping (BLAKE2s-256 and Streebog use the 256-bit and
/// 512-bit digests respectively) but MUST be treated as unverified until
/// their P1 fixtures unlock.
pub fn derive_header_key(
    prf_name: &str,
    passphrase: &[u8],
    salt: &[u8; vc_types::consts::SALT_LEN],
    iterations: u32,
    key_len: usize,
) -> VcResult<HeaderKey> {
    debug_assert!(key_len <= 192);
    let mut key = HeaderKey {
        bytes: [0u8; 192],
        len: key_len,
    };
    let out = &mut key.bytes[..key_len];
    match prf_name {
        "SHA-512" => pbkdf2_hmac::<sha2::Sha512>(passphrase, salt, iterations, out),
        "SHA-256" => pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, out),
        "Whirlpool" => pbkdf2_hmac::<whirlpool::Whirlpool>(passphrase, salt, iterations, out),
        // BLAKE2 is a "lazy" digest in RustCrypto; it needs SimpleHmac
        // rather than the eager-core Hmac that pbkdf2_hmac assumes.
        "BLAKE2s-256" => {
            pbkdf2::pbkdf2::<hmac::SimpleHmac<blake2::Blake2s256>>(
                passphrase, salt, iterations, out,
            )
            .map_err(|e| VcError::Internal(format!("pbkdf2: {e}")))?;
        }
        "Streebog" => pbkdf2_hmac::<streebog::Streebog512>(passphrase, salt, iterations, out),
        other => return Err(VcError::Internal(format!("unknown PRF {other}"))),
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_kdf_is_deterministic_and_length_scoped() {
        let salt = [7u8; 64];
        let a = derive_header_key("SHA-512", b"pw", &salt, 1000, 64).unwrap();
        let b = derive_header_key("SHA-512", b"pw", &salt, 1000, 64).unwrap();
        let c = derive_header_key("SHA-512", b"pw", &salt, 1000, 128).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), 64);
        // PBKDF2 output blocks are independent: a longer derivation shares
        // its prefix with a shorter one.
        assert_eq!(&c.as_bytes()[..64], a.as_bytes());
        assert_ne!(a.as_bytes(), &[0u8; 64][..]);
    }

    #[test]
    fn unknown_prf_is_an_error() {
        let salt = [0u8; 64];
        assert!(derive_header_key("RIPEMD-160", b"pw", &salt, 1, 64).is_err());
    }
}
