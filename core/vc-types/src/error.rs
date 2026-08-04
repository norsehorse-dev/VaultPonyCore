use thiserror::Error;

/// The one error type the core speaks. Variants are deliberately
/// user-explainable: "wrong password" is distinct from "corrupt header" is
/// distinct from "this is newer than we support" (planning doc §4, §6).
#[derive(Debug, Error)]
pub enum VcError {
    /// No candidate (PRF x position x scheme) produced a valid header.
    /// Indistinguishable from a wrong password by design of the format.
    #[error("no volume header found — wrong password/PIM, or not a VeraCrypt container")]
    NotFoundOrWrongPassword,

    /// Header decrypted and validated, but its minimum-program-version field
    /// exceeds what this build implements. Report, don't guess.
    #[error("container requires a newer VeraCrypt format (min version {required:#06x}) than supported ({supported:#06x})")]
    VersionTooNew { required: u16, supported: u16 },

    /// Header carries the system-encryption flag; we refuse politely (doc §6).
    #[error("system-encryption volumes are not supported")]
    SystemVolume,

    /// A write was refused to protect a hidden volume, and the outer volume
    /// has switched to read-only (doc §9).
    #[error("write blocked to protect the hidden volume; the volume is now read-only")]
    HiddenVolumeProtected,

    /// Magic matched but a CRC did not — genuine corruption, worth telling
    /// the user about the backup-header restore path.
    #[error(
        "volume header is damaged (CRC mismatch); the embedded backup header may still be intact"
    )]
    HeaderDamaged,

    /// Filesystem inside the container was recognized but is unsupported.
    /// Name it rather than failing generically (doc §4).
    #[error("container holds a {0} filesystem; not supported yet")]
    UnsupportedFilesystem(String),

    /// Filesystem inside the container could not be identified at all.
    #[error("could not identify a filesystem inside the container")]
    UnknownFilesystem,

    #[error("filesystem error: {0}")]
    Filesystem(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal invariant violation. Should never surface to users.
    #[error("internal error: {0}")]
    Internal(String),
}

pub type VcResult<T> = Result<T, VcError>;
