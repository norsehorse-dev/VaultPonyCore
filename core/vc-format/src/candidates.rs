//! Candidate enumeration and ordering for the unlock search (doc §6).
//!
//! Ordering: SHA-512 + AES first (the overwhelming default), then by PRF
//! popularity and scheme frequency. The full worst case (wrong password) is
//! the entire matrix, so ordering is a UX feature, not an optimization.

use vc_types::{EncryptionScheme, HeaderPosition, Prf};

/// One cell of the search space.
#[derive(Debug, Clone, Copy)]
pub struct Candidate {
    pub prf: &'static Prf,
    pub scheme: &'static EncryptionScheme,
    pub position: HeaderPosition,
}

/// Enumerate candidates in try-order for a given set of positions.
///
/// Remembered-parameters fast path (cache keyed by salt fingerprint, doc §6)
/// slots in ahead of this — that lives in `vault-core`, which owns app
/// storage; this crate stays pure.
pub fn ordered_candidates(positions: &[HeaderPosition]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for position in positions {
        for prf in vc_types::registry::PRFS {
            for scheme in vc_types::registry::ENCRYPTION_SCHEMES {
                out.push(Candidate {
                    prf,
                    scheme,
                    position: *position,
                });
            }
        }
    }
    // PRFS and ENCRYPTION_SCHEMES are already emitted in popularity order by
    // the generator, so nested iteration yields a reasonable try-order.
    // Refine with real-world data once the parameter cache exists.
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vc_types::HeaderPosition;

    #[test]
    fn sha512_aes_is_first() {
        let c = ordered_candidates(&[HeaderPosition::Primary]);
        assert_eq!(c[0].prf.name, "SHA-512");
        assert_eq!(c[0].scheme.name, "AES");
        assert_eq!(c.len(), 15 * 5);
    }
}
