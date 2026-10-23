//! Decrypted-header parsing and validation against the field table in
//! `vc_types::header::offsets` (doc §6).
//!
//! Validation order: magic, header-fields CRC-32 (bytes 0..188 vs the field
//! at 188), master-key CRC-32 (bytes 192..448 vs the field at 8), version
//! gates, flag gates (refuse system-encryption headers politely).
//!
//! This parser is a fuzz target from day one (doc §13) — it consumes
//! attacker-controlled bytes by definition.

use vc_types::header::{offsets, HEADER_FIELDS_CRC_LEN, MASTER_KEY_AREA_LEN};
use vc_types::{HeaderPosition, VcError, VcResult, VolumeGeometry, VolumeHeader};

/// Highest min-program-version this build accepts (0x010b = the value
/// current VeraCrypt writes for standard volumes). Bump deliberately, with
/// fixture coverage, never speculatively.
pub const SUPPORTED_MIN_PROGRAM_VERSION: u16 = 0x010b;

/// Lowest header format version we accept (doc §4: v5+, the `VERA` era).
pub const MIN_HEADER_VERSION: u16 = 5;

/// System-encryption flag bit (refused; doc §6).
const FLAG_SYSTEM_ENCRYPTION: u32 = 0x1;

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn be64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_be_bytes(a)
}

/// Parse and validate a candidate decrypted header region (448 bytes,
/// starting at the would-be "VERA" magic).
///
/// Returns `NotFoundOrWrongPassword` on magic mismatch (the common case
/// during candidate search — it must be cheap and silent), and the more
/// specific errors once the magic matches.
pub fn parse_decrypted_header(
    decrypted: &[u8; vc_types::consts::HEADER_ENC_LEN],
    position: HeaderPosition,
) -> VcResult<VolumeHeader> {
    parse_header(decrypted, position, false)
}

/// TrueCrypt 6.0 to 7.1a version window (`RequiredProgramVersion` 0x600 to
/// 0x71a), as VeraCrypt 1.25.9's TrueCrypt mode enforced it.
pub const TRUECRYPT_MIN_PROGRAM_VERSION: u16 = 0x0600;
pub const TRUECRYPT_MAX_PROGRAM_VERSION: u16 = 0x071a;

/// [`parse_decrypted_header`] for TrueCrypt mode (plan 6.2): magic "TRUE",
/// header version 4 (TrueCrypt 6.x, no sector-size field: 512) or 5
/// (TrueCrypt 7.x), and the 0x600..=0x71a program-version window. Field
/// offsets and CRCs are the same as VeraCrypt's.
pub fn parse_truecrypt_header(
    decrypted: &[u8; vc_types::consts::HEADER_ENC_LEN],
    position: HeaderPosition,
) -> VcResult<VolumeHeader> {
    parse_header(decrypted, position, true)
}

fn parse_header(
    decrypted: &[u8; vc_types::consts::HEADER_ENC_LEN],
    position: HeaderPosition,
    truecrypt: bool,
) -> VcResult<VolumeHeader> {
    let magic = if truecrypt {
        vc_types::consts::TRUECRYPT_MAGIC
    } else {
        vc_types::consts::HEADER_MAGIC
    };
    if decrypted[offsets::MAGIC..offsets::MAGIC + 4] != magic {
        return Err(VcError::NotFoundOrWrongPassword);
    }
    if truecrypt {
        return parse_truecrypt_fields(decrypted, position);
    }

    // Magic matched: from here on, mismatches are corruption, not "wrong
    // password" (a wrong key garbles the magic with overwhelming odds).
    let fields_crc = crc32fast::hash(&decrypted[..HEADER_FIELDS_CRC_LEN]);
    if fields_crc != be32(decrypted, offsets::HEADER_CRC32) {
        return Err(VcError::HeaderDamaged);
    }
    let master_crc = crc32fast::hash(
        &decrypted[offsets::MASTER_KEYS..offsets::MASTER_KEYS + MASTER_KEY_AREA_LEN],
    );
    if master_crc != be32(decrypted, offsets::MASTER_KEY_CRC32) {
        return Err(VcError::HeaderDamaged);
    }

    let header_version = be16(decrypted, offsets::HEADER_VERSION);
    let min_program_version = be16(decrypted, offsets::MIN_PROGRAM_VERSION);
    if header_version < MIN_HEADER_VERSION {
        // Pre-v5 (TrueCrypt-era) headers are a deliberate non-goal (doc §2).
        return Err(VcError::VersionTooNew {
            required: min_program_version,
            supported: SUPPORTED_MIN_PROGRAM_VERSION,
        });
    }
    if min_program_version > SUPPORTED_MIN_PROGRAM_VERSION {
        return Err(VcError::VersionTooNew {
            required: min_program_version,
            supported: SUPPORTED_MIN_PROGRAM_VERSION,
        });
    }

    let flags = be32(decrypted, offsets::FLAGS);
    if flags & FLAG_SYSTEM_ENCRYPTION != 0 {
        return Err(VcError::SystemVolume);
    }

    let sector_size = be32(decrypted, offsets::SECTOR_SIZE);
    if !vc_types::consts::SECTOR_SIZES.contains(&sector_size) {
        return Err(VcError::HeaderDamaged);
    }

    let mut master_keys = [0u8; MASTER_KEY_AREA_LEN];
    master_keys.copy_from_slice(
        &decrypted[offsets::MASTER_KEYS..offsets::MASTER_KEYS + MASTER_KEY_AREA_LEN],
    );

    Ok(VolumeHeader {
        header_version,
        min_program_version,
        flags,
        geometry: VolumeGeometry {
            volume_size: be64(decrypted, offsets::VOLUME_SIZE),
            encrypted_area_start: be64(decrypted, offsets::ENCRYPTED_AREA_START),
            encrypted_area_size: be64(decrypted, offsets::ENCRYPTED_AREA_SIZE),
            sector_size,
            hidden_volume_size: be64(decrypted, offsets::HIDDEN_VOLUME_SIZE),
        },
        position,
        master_keys,
    })
}

fn parse_truecrypt_fields(
    decrypted: &[u8; vc_types::consts::HEADER_ENC_LEN],
    position: HeaderPosition,
) -> VcResult<VolumeHeader> {
    let header_version = be16(decrypted, offsets::HEADER_VERSION);
    let min_program_version = be16(decrypted, offsets::MIN_PROGRAM_VERSION);
    // Version 5 is the newest TrueCrypt wrote; before 4 (TrueCrypt 5.x and
    // older) the header carries no fields CRC and VeraCrypt never opened it.
    if header_version > 5 {
        return Err(VcError::TrueCryptVersionUnsupported {
            version: min_program_version,
        });
    }
    if header_version < 4 {
        return Err(VcError::TrueCryptVersionUnsupported {
            version: min_program_version,
        });
    }
    let fields_crc = crc32fast::hash(&decrypted[..HEADER_FIELDS_CRC_LEN]);
    if fields_crc != be32(decrypted, offsets::HEADER_CRC32) {
        return Err(VcError::HeaderDamaged);
    }
    let master_crc = crc32fast::hash(
        &decrypted[offsets::MASTER_KEYS..offsets::MASTER_KEYS + MASTER_KEY_AREA_LEN],
    );
    if master_crc != be32(decrypted, offsets::MASTER_KEY_CRC32) {
        return Err(VcError::HeaderDamaged);
    }
    if !(TRUECRYPT_MIN_PROGRAM_VERSION..=TRUECRYPT_MAX_PROGRAM_VERSION)
        .contains(&min_program_version)
    {
        return Err(VcError::TrueCryptVersionUnsupported {
            version: min_program_version,
        });
    }
    let flags = be32(decrypted, offsets::FLAGS);
    if flags & FLAG_SYSTEM_ENCRYPTION != 0 {
        return Err(VcError::SystemVolume);
    }
    let sector_size = if header_version >= 5 {
        be32(decrypted, offsets::SECTOR_SIZE)
    } else {
        512
    };
    if !vc_types::consts::SECTOR_SIZES.contains(&sector_size) {
        return Err(VcError::HeaderDamaged);
    }
    let mut master_keys = [0u8; MASTER_KEY_AREA_LEN];
    master_keys.copy_from_slice(
        &decrypted[offsets::MASTER_KEYS..offsets::MASTER_KEYS + MASTER_KEY_AREA_LEN],
    );
    Ok(VolumeHeader {
        header_version,
        min_program_version,
        flags,
        geometry: VolumeGeometry {
            volume_size: be64(decrypted, offsets::VOLUME_SIZE),
            encrypted_area_start: be64(decrypted, offsets::ENCRYPTED_AREA_START),
            encrypted_area_size: be64(decrypted, offsets::ENCRYPTED_AREA_SIZE),
            sector_size,
            hidden_volume_size: be64(decrypted, offsets::HIDDEN_VOLUME_SIZE),
        },
        position,
        master_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically valid decrypted header for tests.
    fn valid_header_bytes() -> [u8; 448] {
        let mut h = [0u8; 448];
        h[0..4].copy_from_slice(b"VERA");
        h[4..6].copy_from_slice(&5u16.to_be_bytes());
        h[6..8].copy_from_slice(&0x010bu16.to_be_bytes());
        h[36..44].copy_from_slice(&(16u64 * 1024 * 1024).to_be_bytes());
        h[44..52].copy_from_slice(&131072u64.to_be_bytes());
        h[52..60].copy_from_slice(&(16u64 * 1024 * 1024 - 262144).to_be_bytes());
        h[64..68].copy_from_slice(&512u32.to_be_bytes());
        for (i, b) in h[192..448].iter_mut().enumerate() {
            *b = i as u8;
        }
        let mk_crc = crc32fast::hash(&h[192..448]);
        h[8..12].copy_from_slice(&mk_crc.to_be_bytes());
        let f_crc = crc32fast::hash(&h[..188]);
        h[188..192].copy_from_slice(&f_crc.to_be_bytes());
        h
    }

    #[test]
    fn parses_valid_header() {
        let h = valid_header_bytes();
        let parsed = parse_decrypted_header(&h, HeaderPosition::Primary).unwrap();
        assert_eq!(parsed.header_version, 5);
        assert_eq!(parsed.geometry.sector_size, 512);
        assert_eq!(parsed.geometry.encrypted_area_start, 131072);
        assert_eq!(parsed.master_keys[1], 1);
    }

    #[test]
    fn bad_magic_is_wrong_password() {
        let mut h = valid_header_bytes();
        h[0] = b'X';
        assert!(matches!(
            parse_decrypted_header(&h, HeaderPosition::Primary),
            Err(VcError::NotFoundOrWrongPassword)
        ));
    }

    #[test]
    fn bad_crc_is_damage_not_wrong_password() {
        let mut h = valid_header_bytes();
        h[100] ^= 0xFF; // corrupt a field the CRC covers
        assert!(matches!(
            parse_decrypted_header(&h, HeaderPosition::Primary),
            Err(VcError::HeaderDamaged)
        ));
    }

    #[test]
    fn system_flag_refused() {
        let mut h = valid_header_bytes();
        h[60..64].copy_from_slice(&1u32.to_be_bytes());
        let f_crc = crc32fast::hash(&h[..188]);
        h[188..192].copy_from_slice(&f_crc.to_be_bytes());
        assert!(matches!(
            parse_decrypted_header(&h, HeaderPosition::Primary),
            Err(VcError::SystemVolume)
        ));
    }

    fn truecrypt_header_bytes(version: u16, program: u16) -> [u8; 448] {
        let mut h = valid_header_bytes();
        h[0..4].copy_from_slice(b"TRUE");
        h[4..6].copy_from_slice(&version.to_be_bytes());
        h[6..8].copy_from_slice(&program.to_be_bytes());
        if version < 5 {
            h[64..68].copy_from_slice(&0u32.to_be_bytes());
        }
        let f_crc = crc32fast::hash(&h[..188]);
        h[188..192].copy_from_slice(&f_crc.to_be_bytes());
        h
    }

    #[test]
    fn truecrypt_headers_parse_only_in_truecrypt_mode() {
        let h = truecrypt_header_bytes(5, 0x071a);
        let parsed = parse_truecrypt_header(&h, HeaderPosition::Primary).unwrap();
        assert_eq!(parsed.header_version, 5);
        assert_eq!(parsed.geometry.sector_size, 512);
        assert!(matches!(
            parse_decrypted_header(&h, HeaderPosition::Primary),
            Err(VcError::NotFoundOrWrongPassword)
        ));
        let v = valid_header_bytes();
        assert!(matches!(
            parse_truecrypt_header(&v, HeaderPosition::Primary),
            Err(VcError::NotFoundOrWrongPassword)
        ));
    }

    #[test]
    fn truecrypt_6_header_has_no_sector_size_field() {
        let h = truecrypt_header_bytes(4, 0x0600);
        let parsed = parse_truecrypt_header(&h, HeaderPosition::Hidden).unwrap();
        assert_eq!(parsed.geometry.sector_size, 512);
    }

    #[test]
    fn truecrypt_version_window_matches_veracrypt_1_25_9() {
        for (version, program) in [(5u16, 0x0500u16), (5, 0x0800), (3, 0x0500), (6, 0x0600)] {
            let h = truecrypt_header_bytes(version, program);
            assert!(
                matches!(
                    parse_truecrypt_header(&h, HeaderPosition::Primary),
                    Err(VcError::TrueCryptVersionUnsupported { .. })
                ),
                "{version} {program:#x}"
            );
        }
    }

    #[test]
    fn future_version_named_clearly() {
        let mut h = valid_header_bytes();
        h[6..8].copy_from_slice(&0x0200u16.to_be_bytes());
        let f_crc = crc32fast::hash(&h[..188]);
        h[188..192].copy_from_slice(&f_crc.to_be_bytes());
        assert!(matches!(
            parse_decrypted_header(&h, HeaderPosition::Primary),
            Err(VcError::VersionTooNew {
                required: 0x0200,
                ..
            })
        ));
    }
}
