//! Volume header layout (planning doc §6).
//!
//! Field offsets below are relative to the start of the *decrypted* header
//! (i.e. after the 64-byte salt, offset 0 = the "VERA" magic). The table is
//! encoded here once; `vc-format` does the parsing and CRC verification, and
//! the fixture corpus is the ground truth for every value.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte offsets within the decrypted 448-byte header.
pub mod offsets {
    /// ASCII "VERA".
    pub const MAGIC: usize = 0;
    /// Volume header format version (big-endian u16).
    pub const HEADER_VERSION: usize = 4;
    /// Minimum program version required to mount (big-endian u16).
    pub const MIN_PROGRAM_VERSION: usize = 6;
    /// CRC-32 of the master key area (bytes 192..=447).
    pub const MASTER_KEY_CRC32: usize = 8;
    /// Reserved (formerly volume creation time).
    pub const RESERVED_1: usize = 12;
    /// Reserved (formerly header creation time).
    pub const RESERVED_2: usize = 20;
    /// Size of the hidden volume in bytes (0 for normal volumes).
    pub const HIDDEN_VOLUME_SIZE: usize = 28;
    /// Size of the volume in bytes.
    pub const VOLUME_SIZE: usize = 36;
    /// Byte offset of the start of the encrypted data area.
    pub const ENCRYPTED_AREA_START: usize = 44;
    /// Size of the encrypted data area in bytes.
    pub const ENCRYPTED_AREA_SIZE: usize = 52;
    /// Flag bits (bit 0: system encryption; bit 1: non-system in-place).
    pub const FLAGS: usize = 60;
    /// Sector size in bytes (big-endian u32).
    pub const SECTOR_SIZE: usize = 64;
    /// CRC-32 of decrypted header bytes 0..188 (fields region).
    /// Volume-absolute offset 252; the published table is absolute from the
    /// container start, these are relative to the decrypted region (−64).
    pub const HEADER_CRC32: usize = 188;
    /// Concatenated master keys (256 bytes): all primary keys, then all
    /// secondary (XTS tweak) keys. Volume-absolute offset 256.
    pub const MASTER_KEYS: usize = 192;
}

/// Length of the fields region covered by `offsets::HEADER_CRC32`.
pub const HEADER_FIELDS_CRC_LEN: usize = 188;

/// Length of the master key area at `offsets::MASTER_KEYS`.
pub const MASTER_KEY_AREA_LEN: usize = 256;

/// Where a header candidate was found in the container (doc §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderPosition {
    /// Offset 0.
    Primary,
    /// Offset 64 KiB. Unlocking here yields the hidden volume (P8).
    Hidden,
    /// size − 128 KiB. Used for recovery.
    BackupPrimary,
    /// size − 64 KiB. Backup of a hidden header.
    BackupHidden,
}

impl HeaderPosition {
    /// Whether this position addresses the hidden volume rather than the
    /// outer/normal one. Used only internally — never surfaced in a way
    /// that reveals a hidden volume's existence (doc §11).
    pub fn is_hidden(self) -> bool {
        matches!(self, HeaderPosition::Hidden | HeaderPosition::BackupHidden)
    }
}

/// Geometry needed by the data path, extracted from a validated header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeGeometry {
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_size: u64,
    pub sector_size: u32,
    pub hidden_volume_size: u64,
}

/// A fully parsed, CRC-validated volume header.
///
/// Holds the master key material; zeroized on drop. Keep instances scoped
/// as tightly as possible (doc §11 — minimal copies).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VolumeHeader {
    pub header_version: u16,
    pub min_program_version: u16,
    pub flags: u32,
    #[zeroize(skip)]
    pub geometry: VolumeGeometry,
    #[zeroize(skip)]
    pub position: HeaderPosition,
    /// Raw 256-byte master key area; the scheme decides how it is split.
    pub master_keys: [u8; MASTER_KEY_AREA_LEN],
}

impl std::fmt::Debug for VolumeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log key material (doc §11).
        f.debug_struct("VolumeHeader")
            .field("header_version", &self.header_version)
            .field("min_program_version", &self.min_program_version)
            .field("flags", &self.flags)
            .field("geometry", &self.geometry)
            .field("position", &self.position)
            .field("master_keys", &"[redacted]")
            .finish()
    }
}
