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

use std::sync::atomic::{AtomicBool, Ordering};
use vc_types::{consts, HeaderPosition, KdfFilter, VcError, VcResult, VolumeHeader};

/// Everything the user supplies to an unlock attempt. Wiped on drop by the
/// caller (`vault-core` owns the lifecycle; doc §11).
pub struct UnlockSecret<'a> {
    pub passphrase: &'a [u8],
    /// PIM; 0 means "use the PRF default schedule".
    pub pim: u32,
    /// Which KDFs the search may try. `Auto` tries everything; narrowing it
    /// is how a user who knows their volume skips the other KDFs' cost.
    pub kdf: KdfFilter,
    /// Set from another thread to stop the search. Checked before every
    /// derivation, so it takes effect within one derivation (one Argon2id
    /// pass set cannot be interrupted partway).
    pub cancel: Option<&'a AtomicBool>,
    /// TrueCrypt mode (plan 6.2), VeraCrypt's "TrueCrypt mode" checkbox:
    /// look for TrueCrypt 6.x/7.x headers ("TRUE") with TrueCrypt's PRFs
    /// and iteration counts instead of VeraCrypt ones. `pim` and `kdf` are
    /// ignored (TrueCrypt has neither). Off for every VeraCrypt unlock, so
    /// ordinary unlocks never pay for the extra derivations.
    pub truecrypt: bool,
    /// The VaultPony 1.x keyfile mix of the same input
    /// (`vc_crypto::apply_keyfiles_legacy`), tried only after `passphrase`
    /// finds nothing. Set only when keyfiles are used with a passphrase over
    /// 64 bytes, so the extra sweep is paid only by those inputs, and its
    /// cost depends on what the user typed, never on the container.
    pub legacy_passphrase: Option<&'a [u8]>,
}

impl<'a> UnlockSecret<'a> {
    /// Passphrase + PIM with every KDF allowed and no cancel handle.
    pub fn new(passphrase: &'a [u8], pim: u32) -> Self {
        Self {
            passphrase,
            pim,
            kdf: KdfFilter::Auto,
            cancel: None,
            truecrypt: false,
            legacy_passphrase: None,
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.is_some_and(|c| c.load(Ordering::Relaxed))
    }

    fn check_cancel(&self) -> VcResult<()> {
        if self.cancelled() {
            Err(VcError::Cancelled)
        } else {
            Ok(())
        }
    }
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
    /// A TrueCrypt header (TrueCrypt mode). Such volumes open read-only.
    pub truecrypt: bool,
    /// Unlocked with `UnlockSecret::legacy_passphrase`: a VaultPony 1.x
    /// keyfile mix that VeraCrypt cannot open. Changing the password (the
    /// same one works) rewrites the header with the VeraCrypt mix.
    pub legacy_keyfile_mix: bool,
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
///
/// When the secret carries a `legacy_passphrase`, a full miss with the
/// VeraCrypt mix is followed by the same search with the 1.x mix. Progress
/// then counts both sweeps from the start, so the bar never runs backwards.
pub fn find_header_at(
    container: &mut dyn vc_io::BlockDevice,
    secret: &UnlockSecret<'_>,
    positions: &[HeaderPosition],
    progress: &mut UnlockProgress<'_>,
) -> VcResult<FoundHeader> {
    let Some(legacy) = secret.legacy_passphrase else {
        return search(container, secret, positions, progress);
    };
    let mut done = 0usize;
    let first = search(container, secret, positions, &mut |i, n, prf| {
        done = n;
        progress(i, n * 2, prf)
    });
    match first {
        Err(VcError::NotFoundOrWrongPassword) => {}
        other => return other,
    }
    let legacy_secret = UnlockSecret {
        passphrase: legacy,
        legacy_passphrase: None,
        ..*secret
    };
    let mut found = search(container, &legacy_secret, positions, &mut |i, n, prf| {
        progress(done + i, done + n, prf)
    })?;
    found.legacy_keyfile_mix = true;
    Ok(found)
}

fn search(
    container: &mut dyn vc_io::BlockDevice,
    secret: &UnlockSecret<'_>,
    positions: &[HeaderPosition],
    progress: &mut UnlockProgress<'_>,
) -> VcResult<FoundHeader> {
    let len = container.len()?;

    let truecrypt = secret.truecrypt;
    let supported: Vec<&'static vc_types::EncryptionScheme> =
        vc_types::registry::ENCRYPTION_SCHEMES
            .iter()
            .filter(|s| vc_crypto::SchemeXts::supported(s))
            .filter(|s| !truecrypt || vc_types::registry::is_truecrypt_scheme(s))
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
        slots.push(Slot {
            position,
            salt,
            enc,
        });
    }

    let prfs: Vec<&'static vc_types::Prf> = if truecrypt {
        vc_types::registry::TRUECRYPT_PRFS.iter().collect()
    } else {
        vc_types::registry::PRFS
            .iter()
            .filter(|p| secret.kdf.allows(p))
            .collect()
    };
    let total = slots.len() * prfs.len();

    // A magic match with a bad CRC or refused flags is a *finding*, not a
    // miss: remember the most specific error to surface if nothing unlocks.
    let mut best_finding: Option<VcError> = None;
    let mut step = 0usize;

    // The first allowed KDF gets the fast path when it is PBKDF2 (SHA-512
    // unless filtered out). An Argon2id-only search has no fast path: it
    // starts straight at the sequential sweep below.
    let mut rest = &prfs[..];
    if let Some(&default_prf) = prfs.first().filter(|p| p.kdf == vc_types::Kdf::Pbkdf2) {
        rest = &prfs[1..];

        // Fast path: the default PRF at the primary slot alone. A stock
        // SHA-512 container opened with its outer/normal password returns
        // here after a single derivation — the cheapest possible unlock,
        // with no regression on low-core devices.
        if let Some(first) = slots.first() {
            secret.check_cancel()?;
            progress(step, total, default_prf.name);
            step += 1;
            let key = derive_for(default_prf, secret, &first.salt, max_key_len)?;
            match try_schemes(&supported, &key, &first.enc, first.position, truecrypt) {
                SchemeOutcome::Found(header, scheme) => {
                    return Ok(FoundHeader {
                        header: *header,
                        scheme,
                        prf: default_prf,
                        truecrypt,
                        legacy_keyfile_mix: false,
                    })
                }
                SchemeOutcome::Finding(e) => best_finding = Some(e),
                SchemeOutcome::Miss => {}
            }
        }

        // Default PRF across the *remaining* slots, in parallel. This is
        // where a hidden SHA-512 volume is found — its header lives in the
        // Hidden slot, so sweeping the default PRF straight there means the
        // hidden unlock no longer waits for the other PRFs to be tried at
        // the primary slot first (that wait was the bulk of the extra
        // hidden-unlock latency).
        if slots.len() > 1 {
            secret.check_cancel()?;
            let others = &slots[1..];
            let keys: Vec<VcResult<vc_crypto::HeaderKey>> = std::thread::scope(|s| {
                let handles: Vec<_> = others
                    .iter()
                    .map(|slot| {
                        s.spawn(|| derive_for(default_prf, secret, &slot.salt, max_key_len))
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            for (slot, key) in others.iter().zip(keys) {
                progress(step, total, default_prf.name);
                step += 1;
                match try_schemes(&supported, &key?, &slot.enc, slot.position, truecrypt) {
                    SchemeOutcome::Found(header, scheme) => {
                        return Ok(FoundHeader {
                            header: *header,
                            scheme,
                            prf: default_prf,
                            truecrypt,
                            legacy_keyfile_mix: false,
                        })
                    }
                    SchemeOutcome::Finding(e) => best_finding = Some(e),
                    SchemeOutcome::Miss => {}
                }
            }
        }
    }

    // Remaining KDFs, each swept across every slot. A wrong password reaches
    // the end of this, deriving every (KDF, slot) pair the filter allows
    // before failing — so unlock time is independent of whether a hidden
    // volume exists, and probing the hidden slot leaves no trace (doc §11).
    //
    // PBKDF2 PRFs sweep the slots in parallel. Argon2id sweeps them one at a
    // time through a single reused buffer: at the default PIM each derivation
    // holds 416 MiB, so four slots at once would need ~1.6 GiB (4 GiB at the
    // 1 GiB cap), more than many phones can give an app.
    for &prf in rest {
        secret.check_cancel()?;
        if prf.kdf == vc_types::Kdf::Argon2id {
            let mut memory = vc_crypto::Argon2Memory::for_pim(secret.pim)?;
            for slot in &slots {
                secret.check_cancel()?;
                progress(step, total, prf.name);
                step += 1;
                let key = vc_crypto::derive_argon2id(
                    &mut memory,
                    secret.passphrase,
                    &slot.salt,
                    secret.pim,
                    max_key_len,
                )?;
                match try_schemes(&supported, &key, &slot.enc, slot.position, truecrypt) {
                    SchemeOutcome::Found(header, scheme) => {
                        return Ok(FoundHeader {
                            header: *header,
                            scheme,
                            prf,
                            truecrypt,
                            legacy_keyfile_mix: false,
                        })
                    }
                    SchemeOutcome::Finding(e) => best_finding = Some(e),
                    SchemeOutcome::Miss => {}
                }
            }
            continue;
        }
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
            match try_schemes(&supported, &key?, &slot.enc, slot.position, truecrypt) {
                SchemeOutcome::Found(header, scheme) => {
                    return Ok(FoundHeader {
                        header: *header,
                        scheme,
                        prf,
                        truecrypt,
                        legacy_keyfile_mix: false,
                    })
                }
                SchemeOutcome::Finding(e) => best_finding = Some(e),
                SchemeOutcome::Miss => {}
            }
        }
    }

    // A cancel that landed during the last derivation still wins over a
    // wrong-password verdict: the user asked to stop, not to be told no.
    secret.check_cancel()?;
    Err(best_finding.unwrap_or(VcError::NotFoundOrWrongPassword))
}

fn derive_for(
    prf: &vc_types::Prf,
    secret: &UnlockSecret<'_>,
    salt: &[u8; consts::SALT_LEN],
    key_len: usize,
) -> VcResult<vc_crypto::HeaderKey> {
    if secret.truecrypt {
        return vc_crypto::derive_truecrypt_header_key(prf, secret.passphrase, salt, key_len);
    }
    vc_crypto::derive_header_key_for(prf, secret.passphrase, salt, secret.pim, key_len)
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
    truecrypt: bool,
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
        let parsed = if truecrypt {
            parse::parse_truecrypt_header(&dec, position)
        } else {
            parse::parse_decrypted_header(&dec, position)
        };
        match parsed {
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
