//! Container probing: unlock the header, identify the filesystem, hand back
//! displayable facts and nothing secret. Powers `vaultpony info` (doc §10 —
//! the support tool: "run this, paste the output").

use std::path::Path;
use vc_format::{find_header, UnlockProgress, UnlockSecret};
use vc_fs::FsKind;
use vc_io::{BlockDevice, FileDevice};
use vc_types::{HeaderPosition, VcResult, VolumeGeometry};

/// Which copy of the header validated — the recovery-relevant distinction,
/// with the hidden/normal distinction deliberately collapsed. `info` output
/// is meant to be pasted into a support thread (doc §10), so it must never
/// reveal that a hidden volume exists (doc §11): Primary and Hidden both
/// report `Primary`, the two backups both report `Backup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderSource {
    Primary,
    Backup,
}

impl From<HeaderPosition> for HeaderSource {
    fn from(p: HeaderPosition) -> Self {
        match p {
            HeaderPosition::Primary | HeaderPosition::Hidden => HeaderSource::Primary,
            HeaderPosition::BackupPrimary | HeaderPosition::BackupHidden => HeaderSource::Backup,
        }
    }
}

/// Displayable probe result. Contains no key material and no paths — safe
/// to print, safe to paste into a support thread.
#[derive(Debug)]
pub struct VolumeInfo {
    pub scheme: &'static str,
    pub prf: &'static str,
    pub source: HeaderSource,
    pub header_version: u16,
    pub min_program_version: u16,
    pub geometry: VolumeGeometry,
    pub filesystem: FsKind,
}

/// Unlock the container's header and sniff the filesystem inside.
///
/// The decrypted first sectors are used only for FS detection and dropped;
/// master keys live exactly as long as this function.
pub fn probe(
    path: &Path,
    passphrase: &[u8],
    pim: u32,
    progress: &mut UnlockProgress<'_>,
) -> VcResult<VolumeInfo> {
    let mut dev = FileDevice::open_read(path)?;
    let found = find_header(&mut dev, &UnlockSecret { passphrase, pim }, progress)?;

    // Decrypt the first 4 KiB of the data area to identify the filesystem.
    // Data-unit numbers are absolute: container offset / 512 (doc §6).
    let geo = found.header.geometry;
    let mut boot = vec![0u8; 4096];
    dev.read_at(geo.encrypted_area_start, &mut boot)?;
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )?;
    xts.decrypt_units(
        &mut boot,
        geo.encrypted_area_start / vc_types::consts::XTS_DATA_UNIT_LEN as u64,
    );
    let filesystem = vc_fs::detect::sniff(&boot);

    Ok(VolumeInfo {
        scheme: found.scheme.name,
        prf: found.prf.name,
        source: found.header.position.into(),
        header_version: found.header.header_version,
        min_program_version: found.header.min_program_version,
        geometry: geo,
        filesystem,
    })
}
