//! Cipher / PRF registry (planning doc §4).
//!
//! The enums are handwritten; the *table* of supported combinations lives in
//! [`generated`], which is emitted by `tools/gen-fixtures/gen_matrix.py` from
//! a pinned VeraCrypt source checkout. Do not hand-edit the generated module —
//! rerun the generator so upstream changes surface as diffs (doc §4).

mod generated;

pub use generated::{ENCRYPTION_SCHEMES, PRFS};

/// Base block ciphers, all used in XTS mode with 512-byte data units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    Aes,
    Serpent,
    Twofish,
    Camellia,
    Kuznyechik,
}

impl Cipher {
    pub const fn name(self) -> &'static str {
        match self {
            Cipher::Aes => "AES",
            Cipher::Serpent => "Serpent",
            Cipher::Twofish => "Twofish",
            Cipher::Camellia => "Camellia",
            Cipher::Kuznyechik => "Kuznyechik",
        }
    }
}

/// A cipher or cascade as VeraCrypt names it. Cascades encrypt with the
/// listed ciphers applied in order (last listed is outermost on disk —
/// verify direction against fixtures before the first data-path test).
/// Each layer gets an independent XTS key pair (doc §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EncryptionScheme {
    pub name: &'static str,
    /// Innermost-first list of ciphers.
    pub layers: &'static [Cipher],
}

impl EncryptionScheme {
    /// Total master-key bytes this scheme consumes from the 256-byte area:
    /// 64 per layer (two 256-bit XTS keys).
    pub const fn key_bytes(&self) -> usize {
        self.layers.len() * 64
    }
}

/// Password-hash PRFs used for header-key derivation (PBKDF2), current
/// VeraCrypt 1.26.x set. RIPEMD-160 dropped upstream; legacy support is a
/// deliberate non-goal for now (doc §2, §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prf {
    pub name: &'static str,
    /// PBKDF2 iterations with no PIM (the upstream default schedule).
    pub default_iterations: u32,
    /// Whether the unlock search should try this PRF early (doc §6 ordering).
    pub popularity_rank: u8,
}

/// Iterations for a given PIM under the non-system schedule (doc §4):
/// `15000 + PIM * 1000`; PIM 0/absent means the PRF default.
pub const fn iterations_for_pim(prf: &Prf, pim: u32) -> u32 {
    if pim == 0 {
        prf.default_iterations
    } else {
        crate::consts::PIM_ITER_BASE + pim * crate::consts::PIM_ITER_PER_UNIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scheme_fits_master_key_area() {
        for s in ENCRYPTION_SCHEMES {
            assert!(
                s.key_bytes() <= crate::header::MASTER_KEY_AREA_LEN,
                "{} needs {} key bytes",
                s.name,
                s.key_bytes()
            );
        }
    }

    #[test]
    fn expected_matrix_size() {
        // 5 single ciphers + 10 cascades, 5 PRFs (doc §4). If the generator
        // produces something else, upstream changed — investigate, don't
        // silently accept.
        assert_eq!(ENCRYPTION_SCHEMES.len(), 15);
        assert_eq!(PRFS.len(), 5);
    }

    #[test]
    fn pim_schedule() {
        let sha512 = PRFS.iter().find(|p| p.name == "SHA-512").unwrap();
        assert_eq!(iterations_for_pim(sha512, 0), sha512.default_iterations);
        assert_eq!(iterations_for_pim(sha512, 485), 500_000);
    }
}
