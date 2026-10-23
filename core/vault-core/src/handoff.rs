//! Key handoff between two processes on one device (iOS File Provider, rc3).
//!
//! The app unlocks a container (the KDF needs far more memory than a File
//! Provider extension is allowed), then hands the extension what it needs to
//! open the same volume without the password: the scheme, the master keys,
//! the geometry, and a fingerprint of the container. The extension gets its
//! own fd to the container next to the blob and rebuilds the decrypted view.
//!
//! The blob holds master keys. It never touches disk: it is built in the
//! app's memory, crosses one XPC call, and is wiped once parsed. Key
//! retention is off unless the process opts in ([`enable_handoff`]), so the
//! Android and desktop shells keep the old rule that master keys live only
//! inside the XTS engine. THREAT_MODEL.md, "Key handoff to the iOS File
//! Provider extension", argues the change.

use std::sync::atomic::{AtomicBool, Ordering};
use vc_types::{consts, EncryptionScheme, Prf, VcError, VcResult, VolumeGeometry};
use zeroize::Zeroizing;

static HANDOFF_ENABLED: AtomicBool = AtomicBool::new(false);

/// Let sessions unlocked from now on keep a copy of their master keys so
/// they can be exported with [`crate::Session::export_handoff`]. Off by
/// default; only the iOS app turns it on.
pub fn enable_handoff(on: bool) {
    HANDOFF_ENABLED.store(on, Ordering::Relaxed);
}

pub(crate) fn handoff_enabled() -> bool {
    HANDOFF_ENABLED.load(Ordering::Relaxed)
}

const MAGIC: &[u8; 3] = b"VPH";
const VERSION: u8 = 1;
const FLAG_HIDDEN: u8 = 1;
const FLAG_PROTECTED: u8 = 2;
const FLAG_TRIPPED: u8 = 4;
const FLAG_TRUECRYPT: u8 = 8;

/// What a session remembers about how it was opened. `keys` is empty unless
/// handoff was enabled when the session was unlocked.
pub(crate) struct KeyRecord {
    pub keys: Zeroizing<Vec<u8>>,
    pub scheme: &'static EncryptionScheme,
    pub prf: &'static Prf,
    pub geometry: VolumeGeometry,
    pub header_offset: u64,
    pub salt: [u8; consts::SALT_LEN],
    pub container_len: u64,
    pub hidden: bool,
    /// Outer-protected sessions: the shielded range in data-area offsets.
    pub protected: Option<(u64, u64)>,
    /// Opened in TrueCrypt mode: `prf` is from `TRUECRYPT_PRFS`, and the
    /// importing process opens the volume read-only too.
    pub truecrypt: bool,
}

impl KeyRecord {
    pub fn encode(&self, tripped: bool) -> VcResult<Zeroizing<Vec<u8>>> {
        if self.keys.is_empty() {
            return Err(VcError::Internal(
                "handoff not enabled for this session".into(),
            ));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        let mut flags = 0u8;
        if self.hidden {
            flags |= FLAG_HIDDEN;
        }
        if self.protected.is_some() {
            flags |= FLAG_PROTECTED;
        }
        if tripped {
            flags |= FLAG_TRIPPED;
        }
        if self.truecrypt {
            flags |= FLAG_TRUECRYPT;
        }
        out.push(flags);
        put_str(&mut out, self.scheme.name);
        put_str(&mut out, self.prf.name);
        out.extend_from_slice(&(self.keys.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.keys);
        let g = &self.geometry;
        out.extend_from_slice(&g.volume_size.to_le_bytes());
        out.extend_from_slice(&g.encrypted_area_start.to_le_bytes());
        out.extend_from_slice(&g.encrypted_area_size.to_le_bytes());
        out.extend_from_slice(&g.sector_size.to_le_bytes());
        out.extend_from_slice(&g.hidden_volume_size.to_le_bytes());
        out.extend_from_slice(&self.header_offset.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.container_len.to_le_bytes());
        if let Some((start, len)) = self.protected {
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
        }
        Ok(out)
    }

    /// Parse a blob from [`encode`](Self::encode). Returns the record and the
    /// tripped flag. Errors are deliberately coarse.
    pub fn decode(blob: &[u8]) -> VcResult<(Self, bool)> {
        let bad = || VcError::Internal("malformed handoff".into());
        let mut r = Reader { buf: blob, pos: 0 };
        if r.take(3).ok_or_else(bad)? != MAGIC || r.u8().ok_or_else(bad)? != VERSION {
            return Err(bad());
        }
        let flags = r.u8().ok_or_else(bad)?;
        let scheme_name = r.str().ok_or_else(bad)?;
        let prf_name = r.str().ok_or_else(bad)?;
        let scheme = vc_types::registry::ENCRYPTION_SCHEMES
            .iter()
            .find(|s| s.name == scheme_name)
            .ok_or_else(bad)?;
        let truecrypt = flags & FLAG_TRUECRYPT != 0;
        let prfs: &'static [Prf] = if truecrypt {
            &vc_types::registry::TRUECRYPT_PRFS
        } else {
            vc_types::registry::PRFS
        };
        let prf = prfs.iter().find(|p| p.name == prf_name).ok_or_else(bad)?;
        if truecrypt
            && (flags & FLAG_PROTECTED != 0 || !vc_types::registry::is_truecrypt_scheme(scheme))
        {
            return Err(bad());
        }
        let key_len = r.u16().ok_or_else(bad)? as usize;
        if key_len != scheme.key_bytes() {
            return Err(bad());
        }
        let keys = Zeroizing::new(r.take(key_len).ok_or_else(bad)?.to_vec());
        let geometry = VolumeGeometry {
            volume_size: r.u64().ok_or_else(bad)?,
            encrypted_area_start: r.u64().ok_or_else(bad)?,
            encrypted_area_size: r.u64().ok_or_else(bad)?,
            sector_size: r.u32().ok_or_else(bad)?,
            hidden_volume_size: r.u64().ok_or_else(bad)?,
        };
        let header_offset = r.u64().ok_or_else(bad)?;
        let mut salt = [0u8; consts::SALT_LEN];
        salt.copy_from_slice(r.take(consts::SALT_LEN).ok_or_else(bad)?);
        let container_len = r.u64().ok_or_else(bad)?;
        let protected = if flags & FLAG_PROTECTED != 0 {
            Some((r.u64().ok_or_else(bad)?, r.u64().ok_or_else(bad)?))
        } else {
            None
        };
        if r.pos != blob.len() {
            return Err(bad());
        }
        let end = geometry
            .encrypted_area_start
            .checked_add(geometry.encrypted_area_size)
            .ok_or_else(bad)?;
        if end > container_len {
            return Err(bad());
        }
        if let Some((start, len)) = protected {
            if start
                .checked_add(len)
                .is_none_or(|e| e > geometry.encrypted_area_size)
            {
                return Err(bad());
            }
        }
        Ok((
            Self {
                keys,
                scheme,
                prf,
                geometry,
                header_offset,
                salt,
                container_len,
                hidden: flags & FLAG_HIDDEN != 0,
                protected,
                truecrypt,
            },
            flags & FLAG_TRIPPED != 0,
        ))
    }

    /// Refuse to apply these keys to any file but the one they came from:
    /// same length, and the header salt where the unlocking header was.
    pub fn check_container(&self, dev: &mut dyn vc_io::BlockDevice) -> VcResult<()> {
        if dev.len()? != self.container_len {
            return Err(VcError::NotFoundOrWrongPassword);
        }
        let mut salt = [0u8; consts::SALT_LEN];
        dev.read_at(self.header_offset, &mut salt)?;
        if salt != self.salt {
            return Err(VcError::NotFoundOrWrongPassword);
        }
        Ok(())
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    fn str(&mut self) -> Option<&'a str> {
        let n = self.u8()? as usize;
        std::str::from_utf8(self.take(n)?).ok()
    }
}
