//! Filesystem sniffing on the decrypted data area (doc §4: detect and name
//! unsupported filesystems — "this container holds ext4" beats a generic
//! failure).

use crate::FsKind;

/// Identify the filesystem from its first sectors. `boot` should be at least
/// 1024 bytes (ext superblock starts at 1024; FAT/exFAT/NTFS signatures live
/// in sector 0).
pub fn sniff(boot: &[u8]) -> FsKind {
    if boot.len() >= 11 && &boot[3..11] == b"EXFAT   " {
        return FsKind::Exfat;
    }
    if boot.len() >= 11 && &boot[3..11] == b"NTFS    " {
        return FsKind::Ntfs;
    }
    // ext2/3/4 superblock magic 0xEF53 at offset 1024 + 56.
    if boot.len() >= 1082 && boot[1080] == 0x53 && boot[1081] == 0xEF {
        return FsKind::Ext4;
    }
    // FAT: boot signature plus a plausible BPB. fatfs does real validation;
    // this is only a router.
    if boot.len() >= 512 && boot[510] == 0x55 && boot[511] == 0xAA {
        return FsKind::Fat;
    }
    FsKind::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_exfat_oem() {
        let mut b = vec![0u8; 1088];
        b[3..11].copy_from_slice(b"EXFAT   ");
        assert_eq!(sniff(&b), FsKind::Exfat);
    }

    #[test]
    fn sniffs_ext4_magic() {
        let mut b = vec![0u8; 1088];
        b[1080] = 0x53;
        b[1081] = 0xEF;
        assert_eq!(sniff(&b), FsKind::Ext4);
    }

    #[test]
    fn unknown_on_zeroes() {
        assert_eq!(sniff(&[0u8; 1088]), FsKind::Unknown);
    }
}
