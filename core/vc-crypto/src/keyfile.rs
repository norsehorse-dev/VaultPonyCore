//! Keyfiles (planning doc §4, §2 P10): the VeraCrypt keyfile algorithm —
//! a 64-byte pool mixed from each keyfile's bytes via a running CRC-32
//! register, then added into the passphrase. Bit-for-bit compatible with
//! desktop VeraCrypt (verified by interop tests both directions).

use zeroize::Zeroizing;

/// Keyfile pool size and per-keyfile read cap (VeraCrypt constants).
pub const POOL_SIZE: usize = 64;
pub const MAX_READ: usize = 1024 * 1024;

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
fn mix_into_pool(pool: &mut [u8; POOL_SIZE], write_pos: &mut usize, crc: &mut u32, data: &[u8]) {
    for &b in data.iter().take(MAX_READ) {
        *crc = crc32_update(*crc, b);
        for shift in [24u32, 16, 8, 0] {
            pool[*write_pos] = pool[*write_pos].wrapping_add((*crc >> shift) as u8);
            *write_pos += 1;
            if *write_pos >= POOL_SIZE {
                *write_pos = 0;
            }
        }
    }
}

/// Apply keyfiles to a passphrase, returning the effective secret to feed
/// PBKDF2. With no keyfiles the passphrase is returned unchanged. Matches
/// VeraCrypt: the pool is added (mod 256) to the first 64 passphrase bytes,
/// extending the length to 64 when shorter.
pub fn apply_keyfiles(passphrase: &[u8], keyfiles: &[Vec<u8>]) -> Zeroizing<Vec<u8>> {
    if keyfiles.is_empty() {
        return Zeroizing::new(passphrase.to_vec());
    }
    let mut pool = [0u8; POOL_SIZE];
    for kf in keyfiles {
        let mut write_pos = 0usize;
        let mut crc = 0xFFFF_FFFFu32;
        mix_into_pool(&mut pool, &mut write_pos, &mut crc, kf);
    }
    let out_len = passphrase.len().max(POOL_SIZE);
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
    fn empty_keyfile_still_extends_but_adds_zero_pool() {
        // A zero-length keyfile contributes nothing to the pool, but the
        // presence of *a* keyfile still extends a short passphrase to 64.
        let out = apply_keyfiles(b"pw", &[vec![]]);
        assert_eq!(out.len(), POOL_SIZE);
        assert_eq!(&out[..2], b"pw");
        assert!(out[2..].iter().all(|&b| b == 0));
    }
}
