//! Plain data types shared across the VaultPony core: volume header layout,
//! cipher/PRF registries, volume geometry, and the common error type.
//!
//! This crate has no I/O and no crypto — it is the vocabulary the other
//! crates speak. The header field table is encoded exactly once, here, and
//! verified against the fixture corpus (planning doc §6).

pub mod error;
pub mod header;
pub mod registry;

pub use error::{VcError, VcResult};
pub use header::{HeaderPosition, VolumeGeometry, VolumeHeader};
pub use registry::{Cipher, EncryptionScheme, Prf};

/// Container-level constants (planning doc §6).
pub mod consts {
    /// Salt length preceding the encrypted header.
    pub const SALT_LEN: usize = 64;
    /// Length of the encrypted header (after the salt).
    pub const HEADER_ENC_LEN: usize = 448;
    /// Total header region size: salt + encrypted header.
    pub const HEADER_REGION_LEN: usize = SALT_LEN + HEADER_ENC_LEN;
    /// ASCII "VERA" magic at the start of a successfully decrypted header.
    pub const HEADER_MAGIC: [u8; 4] = *b"VERA";
    /// Offset of the primary header from the start of the container.
    pub const PRIMARY_HEADER_OFFSET: u64 = 0;
    /// Offset of the hidden-volume header from the start of the container.
    pub const HIDDEN_HEADER_OFFSET: u64 = 65_536;
    /// Backup standard header lives at `size - BACKUP_STANDARD_FROM_END`.
    pub const BACKUP_STANDARD_FROM_END: u64 = 131_072;
    /// Backup hidden header lives at `size - BACKUP_HIDDEN_FROM_END`.
    pub const BACKUP_HIDDEN_FROM_END: u64 = 65_536;
    /// Data-unit size for XTS on the data area (independent of sector size).
    pub const XTS_DATA_UNIT_LEN: usize = 512;
    /// Non-system iteration schedule: `15000 + PIM * 1000` (doc §4).
    /// NOTE: verify exact per-PRF defaults against the fixture corpus, not
    /// spec prose, before relying on this anywhere user-visible.
    pub const PIM_ITER_BASE: u32 = 15_000;
    pub const PIM_ITER_PER_UNIT: u32 = 1_000;
    /// Supported sector sizes (doc §4).
    pub const SECTOR_SIZES: [u32; 2] = [512, 4096];
}
