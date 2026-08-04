//! Header discovery, candidate-key derivation orchestration, and header
//! decrypt/validate (planning doc §6).
//!
//! Unlocking is a search problem: nothing in the container states the PRF or
//! scheme, so we derive candidate header keys and test-decrypt until the
//! magic and both CRC-32s check out.

pub mod candidates;
pub mod create;
pub mod decrypted;
pub mod parse;
pub mod protect;
pub mod repair;

pub use create::{create_hidden, create_volume, CreateParams};
pub use decrypted::DecryptedDevice;
pub use protect::ProtectedDevice;

use vc_types::{consts, HeaderPosition, VcError, VcResult, VolumeHeader};

/// Everything the user supplies to an unlock attempt. Wiped on drop by the
/// caller (`vault-core` owns the lifecycle; doc §11).
pub struct UnlockSecret<'a> {
    pub passphrase: &'a [u8],
    /// PIM; 0 means "use the PRF default schedule".
    pub pim: u32,
}

/// Progress callback so a wrong password on an old phone doesn't look like a
/// hang (doc §6): reports (candidate_index, candidate_total, prf_name).
pub type UnlockProgress<'a> = dyn FnMut(usize, usize, &str) + 'a;

/// Byte offset of a header position within a container of `len` bytes, or
/// None when the container is too small to hold it.
pub fn position_offset(position: HeaderPosition, len: u64) -> Option<u64> {
    match position {
        HeaderPosition::Primary => Some(consts::PRIMARY_HEADER_OFFSET),
        HeaderPosition::Hidden => (len
            >= consts::HIDDEN_HEADER_OFFSET + consts::HEADER_REGION_LEN as u64)
            .then_some(consts::HIDDEN_HEADER_OFFSET),
        HeaderPosition::BackupPrimary => len.checked_sub(consts::BACKUP_STANDARD_FROM_END),
        HeaderPosition::BackupHidden => len.checked_sub(consts::BACKUP_HIDDEN_FROM_END),
    }
}

/// A successful header find: the validated header plus which candidate
/// matched, so shells can report and remember the parameters (doc §6).
/// Debug delegates to `VolumeHeader`'s redacting impl — no key material.
#[derive(Debug)]
pub struct FoundHeader {
    pub header: VolumeHeader,
    pub scheme: &'static vc_types::EncryptionScheme,
    pub prf: &'static vc_types::Prf,
}

/// Search for a header that validates. The supplied password alone decides
/// which volume opens: at each position we test-decrypt, and whichever slot
/// validates is the one the user asked for (P8 — hidden volume read).
///
/// Position order is primary, hidden, then the two embedded backups. Every
/// position is probed with the same work whether or not a hidden volume
/// exists, and a wrong password walks the entire list before failing — so
/// timing and the returned error are identical for normal volumes, outer
/// volumes, and containers with no hidden volume at all. Probing the hidden
/// slot leaves no trace (doc §11); nothing here logs a position or the fact
/// that a hidden header matched.
///
/// Key derivation is the entire unlock latency, so the loop is shaped
/// around it: the default PRF (SHA-512) tries alone first — a stock
/// container costs exactly one derivation — then the remaining PRFs derive
/// in parallel across cores (doc §6). Each derivation is sized to the
/// largest supported scheme and every scheme test-decrypts from a prefix
/// of it (PBKDF2 output blocks are independent, so a prefix equals a
/// shorter derivation).
pub fn find_header(
    container: &mut dyn vc_io::BlockDevice,
    secret: &UnlockSecret<'_>,
    progress: &mut UnlockProgress<'_>,
) -> VcResult<FoundHeader> {
    find_header_at(
        container,
        secret,
        &[
            HeaderPosition::Primary,
            HeaderPosition::Hidden,
            HeaderPosition::BackupPrimary,
            HeaderPosition::BackupHidden,
        ],
        progress,
    )
}

/// `find_header` with an explicit position list — the repair tooling probes
/// single positions (e.g. only the embedded backup) through this.
pub fn find_header_at(
    container: &mut dyn vc_io::BlockDevice,
    secret: &UnlockSecret<'_>,
    positions: &[HeaderPosition],
    progress: &mut UnlockProgress<'_>,
) -> VcResult<FoundHeader> {
    let len = container.len()?;

    let supported: Vec<&'static vc_types::EncryptionScheme> =
        vc_types::registry::ENCRYPTION_SCHEMES
            .iter()
            .filter(|s| vc_crypto::SchemeXts::supported(s))
            .collect();
    let max_key_len = supported.iter().map(|s| s.key_bytes()).max().unwrap_or(0);
    if max_key_len == 0 {
        return Err(VcError::Internal(
            "no encryption schemes implemented".into(),
        ));
    }
    // Read each valid position's salt + ciphertext once. These reads are
    // negligible next to key derivation, and gathering them up front lets us
    // derive one PRF across *every* position at once, instead of finishing all
    // PRFs at one position before moving to the next.
    struct Slot {
        position: HeaderPosition,
        salt: [u8; consts::SALT_LEN],
        enc: [u8; consts::HEADER_ENC_LEN],
    }
    let mut slots: Vec<Slot> = Vec::with_capacity(positions.len());
    for &position in positions {
        let Some(offset) = position_offset(position, len) else {
            continue;
        };
        let mut salt = [0u8; consts::SALT_LEN];
        container.read_at(offset, &mut salt)?;
        let mut enc = [0u8; consts::HEADER_ENC_LEN];
        container.read_at(offset + consts::SALT_LEN as u64, &mut enc)?;
        slots.push(Slot { position, salt, enc });
    }

    let prfs = vc_types::registry::PRFS;
    let total = slots.len() * prfs.len();

    // A magic match with a bad CRC or refused flags is a *finding*, not a
    // miss: remember the most specific error to surface if nothing unlocks.
    let mut best_finding: Option<VcError> = None;
    let mut step = 0usize;

    // Fast path: the default PRF (first in popularity order) at the primary
    // slot alone. A stock SHA-512 container opened with its outer/normal
    // password returns here after a single derivation — the cheapest possible
    // unlock, with no regression on low-core devices.
    let default_prf = &prfs[0];
    if let Some(first) = slots.first() {
        progress(step, total, default_prf.name);
        step += 1;
        let key = derive_for(default_prf, secret, &first.salt, max_key_len)?;
        match try_schemes(&supported, &key, &first.enc, first.position) {
            SchemeOutcome::Found(header, scheme) => {
                return Ok(FoundHeader {
                    header: *header,
                    scheme,
                    prf: default_prf,
                })
            }
            SchemeOutcome::Finding(e) => best_finding = Some(e),
            SchemeOutcome::Miss => {}
        }
    }

    // Default PRF across the *remaining* slots, in parallel. This is where a
    // hidden SHA-512 volume is found — its header lives in the Hidden slot, so
    // sweeping the default PRF straight there means the hidden unlock no longer
    // waits for the other PRFs to be tried at the primary slot first (that wait
    // was the bulk of the extra hidden-unlock latency).
    if slots.len() > 1 {
        let rest = &slots[1..];
        let keys: Vec<VcResult<vc_crypto::HeaderKey>> = std::thread::scope(|s| {
            let handles: Vec<_> = rest
                .iter()
                .map(|slot| s.spawn(|| derive_for(default_prf, secret, &slot.salt, max_key_len)))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (slot, key) in rest.iter().zip(keys) {
            progress(step, total, default_prf.name);
            step += 1;
            match try_schemes(&supported, &key?, &slot.enc, slot.position) {
                SchemeOutcome::Found(header, scheme) => {
                    return Ok(FoundHeader {
                        header: *header,
                        scheme,
                        prf: default_prf,
                    })
                }
                SchemeOutcome::Finding(e) => best_finding = Some(e),
                SchemeOutcome::Miss => {}
            }
        }
    }

    // Remaining PRFs, each swept across every slot in parallel. A wrong
    // password reaches the end of this, deriving every (PRF, slot) pair before
    // failing — so unlock time is independent of whether a hidden volume
    // exists, and probing the hidden slot leaves no trace (doc §11).
    for prf in prfs.iter().skip(1) {
        let keys: Vec<VcResult<vc_crypto::HeaderKey>> = std::thread::scope(|s| {
            let handles: Vec<_> = slots
                .iter()
                .map(|slot| s.spawn(|| derive_for(prf, secret, &slot.salt, max_key_len)))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for (slot, key) in slots.iter().zip(keys) {
            progress(step, total, prf.name);
            step += 1;
            match try_schemes(&supported, &key?, &slot.enc, slot.position) {
                SchemeOutcome::Found(header, scheme) => {
                    return Ok(FoundHeader {
                        header: *header,
                        scheme,
                        prf,
                    })
                }
                SchemeOutcome::Finding(e) => best_finding = Some(e),
                SchemeOutcome::Miss => {}
            }
        }
    }

    Err(best_finding.unwrap_or(VcError::NotFoundOrWrongPassword))
}

fn derive_for(
    prf: &vc_types::Prf,
    secret: &UnlockSecret<'_>,
    salt: &[u8; consts::SALT_LEN],
    key_len: usize,
) -> VcResult<vc_crypto::HeaderKey> {
    let iterations = vc_types::registry::iterations_for_pim(prf, secret.pim);
    vc_crypto::derive_header_key(prf.name, secret.passphrase, salt, iterations, key_len)
}

enum SchemeOutcome {
    // Boxed: VolumeHeader is ~320 bytes of key material and this enum is
    // mostly Miss during the search loop.
    Found(Box<VolumeHeader>, &'static vc_types::EncryptionScheme),
    Finding(VcError),
    Miss,
}

fn try_schemes(
    supported: &[&'static vc_types::EncryptionScheme],
    key: &vc_crypto::HeaderKey,
    enc: &[u8; consts::HEADER_ENC_LEN],
    position: HeaderPosition,
) -> SchemeOutcome {
    let mut finding = None;
    for scheme in supported {
        let Ok(xts) = vc_crypto::SchemeXts::new(scheme, &key.as_bytes()[..scheme.key_bytes()])
        else {
            continue;
        };
        // dec holds the decrypted header, including the plaintext master keys
        // for a matching candidate. Wrap it so the frame zeroizes it instead of
        // leaving key material on the stack for freed pages or swap.
        let mut dec = zeroize::Zeroizing::new(*enc);
        xts.decrypt_header(&mut dec);
        match parse::parse_decrypted_header(&dec, position) {
            Ok(header) => return SchemeOutcome::Found(Box::new(header), scheme),
            Err(VcError::NotFoundOrWrongPassword) => continue,
            // Magic matched but validation failed: keep the diagnosis, keep
            // searching (the backup may be intact).
            Err(e) => finding = Some(e),
        }
    }
    match finding {
        Some(e) => SchemeOutcome::Finding(e),
        None => SchemeOutcome::Miss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn position_offsets() {
        let len = 16 * 1024 * 1024u64;
        assert_eq!(position_offset(HeaderPosition::Primary, len), Some(0));
        assert_eq!(
            position_offset(HeaderPosition::BackupPrimary, len),
            Some(len - 131072)
        );
        assert_eq!(
            position_offset(HeaderPosition::BackupHidden, len),
            Some(len - 65536)
        );
        assert_eq!(position_offset(HeaderPosition::Hidden, 1024), None);
    }
}
