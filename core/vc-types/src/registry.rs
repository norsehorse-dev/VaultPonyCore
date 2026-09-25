//! Cipher / PRF registry (planning doc §4).
//!
//! The enums are handwritten; the *table* of supported combinations lives in
//! [`generated`], which is emitted by `tools/gen-fixtures/gen_matrix.py` from
//! a pinned VeraCrypt source checkout. Do not hand-edit the generated module —
//! rerun the generator so upstream changes surface as diffs (doc §4).

mod generated;

pub use generated::{ARGON2_SCHEDULE, ENCRYPTION_SCHEMES, PRFS};

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

/// Which key-derivation function a [`Prf`] entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kdf {
    /// PBKDF2-HMAC over the entry's hash; cost is an iteration count.
    Pbkdf2,
    /// Argon2id v0x13, parallelism 1; cost is memory plus passes, both set by
    /// the PIM through [`ARGON2_SCHEDULE`] (VeraCrypt 1.26.29+).
    Argon2id,
}

/// Which KDFs an unlock search may try. VeraCrypt itself always tries all
/// of them; narrowing is a VaultPony convenience for users who know their
/// volume, because an Argon2id-only search skips the whole PBKDF2 sweep and
/// a PBKDF2-only search skips Argon2id's memory and time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KdfFilter {
    #[default]
    Auto,
    Pbkdf2Only,
    Argon2idOnly,
}

impl KdfFilter {
    pub const fn allows(self, kdf: Kdf) -> bool {
        matches!(
            (self, kdf),
            (KdfFilter::Auto, _)
                | (KdfFilter::Pbkdf2Only, Kdf::Pbkdf2)
                | (KdfFilter::Argon2idOnly, Kdf::Argon2id)
        )
    }
}

/// Header-key derivation candidates, current VeraCrypt 1.26.x set: five
/// PBKDF2 PRFs plus Argon2id. RIPEMD-160 dropped upstream; legacy support is
/// a deliberate non-goal for now (doc §2, §4). The type keeps its PRF name
/// because every caller and the FFI address these entries by `name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prf {
    pub name: &'static str,
    pub kdf: Kdf,
    /// PBKDF2 iterations with no PIM (the upstream default schedule). Zero
    /// for Argon2id, whose cost comes from [`argon2_cost`].
    pub default_iterations: u32,
    /// Whether the unlock search should try this PRF early (doc §6 ordering).
    pub popularity_rank: u8,
}

/// Upstream's PIM -> Argon2id cost mapping (`get_argon2_params` in
/// Pkcs5.c), captured by the generator so a change surfaces as a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Argon2Schedule {
    /// PIM 0 means this PIM.
    pub default_pim: u32,
    pub memory_base_mib: u32,
    pub memory_step_mib: u32,
    pub memory_cap_mib: u32,
    pub passes_base: u32,
    pub passes_divisor: u32,
    /// Last PIM on the stepped pass formula; above it passes grow by one per PIM.
    pub passes_split_pim: u32,
    pub passes_high_base: u32,
    /// Bytes requested from Argon2id for every header, whatever the scheme
    /// needs. Asking for fewer changes the output, not just its length.
    pub output_len: usize,
}

/// Argon2id cost for one derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Argon2Cost {
    pub memory_kib: u32,
    pub passes: u32,
}

impl Argon2Cost {
    /// Memory in MiB, for UI preflight checks and error messages.
    pub const fn memory_mib(&self) -> u32 {
        self.memory_kib / 1024
    }
}

/// Iterations for a given PIM under the non-system schedule (doc §4):
/// `15000 + PIM * 1000`; PIM 0/absent means the PRF default. For Argon2id
/// this is the pass count (what upstream's own `GetIterationCount` reports).
pub const fn iterations_for_pim(prf: &Prf, pim: u32) -> u32 {
    match prf.kdf {
        Kdf::Argon2id => argon2_cost(pim).passes,
        Kdf::Pbkdf2 => {
            if pim == 0 {
                prf.default_iterations
            } else {
                crate::consts::PIM_ITER_BASE + pim * crate::consts::PIM_ITER_PER_UNIT
            }
        }
    }
}

/// Argon2id memory and passes for a PIM, exactly as upstream computes them.
/// Saturates instead of wrapping for absurd PIMs; those fail on memory or
/// time long before the arithmetic matters.
pub const fn argon2_cost(pim: u32) -> Argon2Cost {
    let s = &ARGON2_SCHEDULE;
    let pim = if pim == 0 { s.default_pim } else { pim };
    let steps = pim - 1;
    let mut mib = s
        .memory_base_mib
        .saturating_add(steps.saturating_mul(s.memory_step_mib));
    if mib > s.memory_cap_mib {
        mib = s.memory_cap_mib;
    }
    let passes = if pim <= s.passes_split_pim {
        s.passes_base + steps / s.passes_divisor
    } else {
        s.passes_high_base.saturating_add(pim - s.passes_split_pim)
    };
    Argon2Cost {
        memory_kib: mib * 1024,
        passes,
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
        assert_eq!(PRFS.len(), 6);
    }

    #[test]
    fn every_filter_allows_at_least_one_kdf() {
        for f in [
            KdfFilter::Auto,
            KdfFilter::Pbkdf2Only,
            KdfFilter::Argon2idOnly,
        ] {
            assert!(PRFS.iter().any(|p| f.allows(p.kdf)), "{f:?}");
        }
        assert_eq!(
            PRFS.iter()
                .filter(|p| KdfFilter::Argon2idOnly.allows(p.kdf))
                .count(),
            1
        );
        assert_eq!(
            PRFS.iter()
                .filter(|p| KdfFilter::Pbkdf2Only.allows(p.kdf))
                .count(),
            PRFS.len() - 1
        );
    }

    #[test]
    fn argon2id_is_tried_last() {
        let last = PRFS.last().unwrap();
        assert_eq!(last.kdf, Kdf::Argon2id);
        assert_eq!(last.name, "Argon2id");
        assert!(PRFS[..PRFS.len() - 1].iter().all(|p| p.kdf == Kdf::Pbkdf2));
    }

    #[test]
    fn argon2_schedule_matches_upstream_examples() {
        // The worked examples in upstream's get_argon2_params() comment and
        // the Argon2id spec page.
        let mib = |pim| argon2_cost(pim).memory_mib();
        let passes = |pim| argon2_cost(pim).passes;
        assert_eq!((mib(0), passes(0)), (416, 6));
        assert_eq!((mib(12), passes(12)), (416, 6));
        assert_eq!((mib(1), passes(1)), (64, 3));
        assert_eq!((mib(2), passes(2)), (96, 3));
        assert_eq!((mib(4), passes(4)), (160, 4));
        assert_eq!((mib(31), passes(31)), (1024, 13));
        assert_eq!((mib(32), passes(32)), (1024, 14));
        assert_eq!((mib(40), passes(40)), (1024, 22));
        assert_eq!(argon2_cost(12).memory_kib, 425_984);
        assert_eq!(ARGON2_SCHEDULE.output_len, 192);
    }

    #[test]
    fn argon2_cost_saturates_on_absurd_pim() {
        let c = argon2_cost(u32::MAX);
        assert_eq!(c.memory_mib(), 1024);
        assert_eq!(c.passes, 13 + (u32::MAX - 31));
    }

    #[test]
    fn argon2_schedule_covers_every_scheme() {
        // Upstream refuses Argon2 for a scheme whose key needs more than the
        // fixed output (Volumes.c); every current scheme fits.
        for s in ENCRYPTION_SCHEMES {
            assert!(s.key_bytes() <= ARGON2_SCHEDULE.output_len, "{}", s.name);
        }
    }

    #[test]
    fn pim_schedule() {
        let sha512 = PRFS.iter().find(|p| p.name == "SHA-512").unwrap();
        assert_eq!(iterations_for_pim(sha512, 0), sha512.default_iterations);
        assert_eq!(iterations_for_pim(sha512, 485), 500_000);
    }
}
