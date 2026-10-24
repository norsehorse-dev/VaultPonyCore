//! Keyfiles (planning doc §4, §2 P10): the VeraCrypt keyfile algorithm.
//! A pool is mixed from each keyfile's bytes via a running CRC-32 register,
//! then added into the passphrase. The pool is 64 bytes for passphrases of
//! up to 64 bytes and 128 bytes for longer ones (VeraCrypt's
//! KEYFILE_POOL_LEGACY_SIZE / KEYFILE_POOL_SIZE, chosen by
//! MAX_LEGACY_PASSWORD in Keyfiles.c). Bit-for-bit compatible with desktop
//! VeraCrypt (verified by interop tests both directions).

use zeroize::Zeroizing;

/// Keyfile pool sizes and per-keyfile read cap (VeraCrypt constants).
pub const POOL_SIZE: usize = 64;
pub const POOL_SIZE_LONG: usize = 128;
/// Passphrases longer than this use the 128-byte pool.
pub const MAX_LEGACY_PASSWORD: usize = 64;
pub const MAX_READ: usize = 1024 * 1024;

/// VeraCrypt refuses a keyfile with no bytes; so do we, before any
/// derivation or write.
pub fn check_keyfiles(keyfiles: &[Vec<u8>]) -> vc_types::VcResult<()> {
    if keyfiles.iter().any(|k| k.is_empty()) {
        return Err(vc_types::VcError::EmptyKeyfile);
    }
    Ok(())
}

/// One reflected CRC-32 table entry (poly 0xEDB88320).
fn crc32_tab(index: u32) -> u32 {
    let mut c = index & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            (c >> 1) ^ 0xEDB8_8320
        } else {
            c >> 1
        };
    }
    c
}

/// VeraCrypt's UPDATE_CRC: `tab[(crc ^ byte) & 0xff] ^ (crc >> 8)`, tracking
/// the raw running register (no final XOR — VeraCrypt reads its bytes
/// directly). Register is initialised to 0xFFFFFFFF per keyfile.
fn crc32_update(crc: u32, byte: u8) -> u32 {
    crc32_tab((crc ^ byte as u32) & 0xff) ^ (crc >> 8)
}

/// Fold one keyfile's bytes into the pool at the running write position.
fn mix_into_pool(pool: &mut [u8], write_pos: &mut usize, crc: &mut u32, data: &[u8]) {
    for &b in data.iter().take(MAX_READ) {
        *crc = crc32_update(*crc, b);
        for shift in [24u32, 16, 8, 0] {
            pool[*write_pos] = pool[*write_pos].wrapping_add((*crc >> shift) as u8);
            *write_pos += 1;
            if *write_pos >= pool.len() {
                *write_pos = 0;
            }
        }
    }
}

/// Apply keyfiles to a passphrase, returning the effective secret to feed
/// PBKDF2. With no keyfiles the passphrase is returned unchanged. Matches
/// VeraCrypt: the pool is added (mod 256) to the first pool-size passphrase
/// bytes, extending the length to the pool size when shorter. Callers check
/// for empty keyfiles first (`check_keyfiles`).
pub fn apply_keyfiles(passphrase: &[u8], keyfiles: &[Vec<u8>]) -> Zeroizing<Vec<u8>> {
    let pool_size = if passphrase.len() <= MAX_LEGACY_PASSWORD {
        POOL_SIZE
    } else {
        POOL_SIZE_LONG
    };
    mix(passphrase, keyfiles, pool_size)
}

/// The secret VaultPony 1.x derived for the same input, when it differs
/// from [`apply_keyfiles`]: 1.x always used the 64-byte pool, so a vault it
/// made with keyfiles and a passphrase longer than 64 bytes only opens with
/// this secret (and never opened in VeraCrypt). `None` for every other
/// input, so ordinary unlocks never try a second secret. Unlock code tries
/// this only after the VeraCrypt secret fails; changing the password then
/// rewrites the header with the VeraCrypt mix.
pub fn apply_keyfiles_legacy(
    passphrase: &[u8],
    keyfiles: &[Vec<u8>],
) -> Option<Zeroizing<Vec<u8>>> {
    (!keyfiles.is_empty() && passphrase.len() > MAX_LEGACY_PASSWORD)
        .then(|| mix(passphrase, keyfiles, POOL_SIZE))
}

fn mix(passphrase: &[u8], keyfiles: &[Vec<u8>], pool_size: usize) -> Zeroizing<Vec<u8>> {
    if keyfiles.is_empty() {
        return Zeroizing::new(passphrase.to_vec());
    }
    let mut pool = Zeroizing::new(vec![0u8; pool_size]);
    for kf in keyfiles {
        let mut write_pos = 0usize;
        let mut crc = 0xFFFF_FFFFu32;
        mix_into_pool(&mut pool, &mut write_pos, &mut crc, kf);
    }
    let out_len = passphrase.len().max(pool_size);
    let mut out = Zeroizing::new(vec![0u8; out_len]);
    out[..passphrase.len()].copy_from_slice(passphrase);
    for (i, p) in pool.iter().enumerate() {
        out[i] = out[i].wrapping_add(*p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_keyfiles_is_identity() {
        let out = apply_keyfiles(b"hunter2", &[]);
        assert_eq!(&out[..], b"hunter2");
    }

    #[test]
    fn keyfile_changes_and_extends_the_secret() {
        let out = apply_keyfiles(b"pw", &[vec![0xABu8; 100]]);
        assert_eq!(out.len(), POOL_SIZE); // extended to 64
        assert_ne!(&out[..2], b"pw"); // pool added to the first bytes
    }

    #[test]
    fn long_passphrases_use_the_128_byte_pool() {
        let pw = [b'a'; 65];
        let out = apply_keyfiles(&pw, &[vec![0xABu8; 100]]);
        assert_eq!(out.len(), POOL_SIZE_LONG);
        // Bytes past 64 carry pool bytes, so they differ from a 64-byte pool.
        assert!(out[65..].iter().any(|&b| b != 0));
        let short = apply_keyfiles(&[b'a'; 64], &[vec![0xABu8; 100]]);
        assert_eq!(short.len(), POOL_SIZE);
    }

    #[test]
    fn legacy_secret_only_for_long_passphrases_with_keyfiles() {
        let kf = [vec![0xABu8; 100]];
        assert!(apply_keyfiles_legacy(&[b'a'; 64], &kf).is_none());
        assert!(apply_keyfiles_legacy(&[b'a'; 65], &[]).is_none());
        let pw = [b'a'; 65];
        let legacy = apply_keyfiles_legacy(&pw, &kf).unwrap();
        // 1.x: 64-byte pool, so the passphrase keeps its length and bytes
        // past 64 are untouched.
        assert_eq!(legacy.len(), 65);
        assert_eq!(legacy[64], b'a');
        assert_ne!(&legacy[..], &apply_keyfiles(&pw, &kf)[..]);
        assert_eq!(&legacy[..64], &apply_keyfiles(&pw[..64], &kf)[..64]);
    }

    #[test]
    fn empty_keyfiles_are_refused() {
        assert!(check_keyfiles(&[vec![1], vec![]]).is_err());
        assert!(check_keyfiles(&[vec![1]]).is_ok());
    }

    #[test]
    fn empty_keyfile_still_extends_but_adds_zero_pool() {
        // A zero-length keyfile contributes nothing to the pool, but the
        // presence of *a* keyfile still extends a short passphrase to 64.
        let out = apply_keyfiles(b"pw", &[vec![]]);
        assert_eq!(out.len(), POOL_SIZE);
        assert_eq!(&out[..2], b"pw");
        assert!(out[2..].iter().all(|&b| b == 0));
    }
}
