//! Boot region: main boot sector fields and the VBR checksum sector
//! (exFAT specification §3.1–3.4).

use crate::{ExfatError, ExfatResult, ReadAt};

#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub cluster_heap_offset_sectors: u32,
    pub cluster_count: u32,
    pub root_first_cluster: u32,
}

impl Geometry {
    pub fn cluster_bytes(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Byte offset of a cluster's first byte. Clusters are numbered from 2.
    pub fn cluster_offset(&self, cluster: u32) -> ExfatResult<u64> {
        if cluster < 2 || cluster >= self.cluster_count + 2 {
            return Err(ExfatError::Invalid("cluster number out of range"));
        }
        Ok(
            self.bytes_per_sector as u64 * self.cluster_heap_offset_sectors as u64
                + (cluster as u64 - 2) * self.cluster_bytes(),
        )
    }
}

/// Parse and validate the main boot region: signature fields, geometry
/// ranges, and the repeated VBR checksum in sector 11.
pub fn read_boot_region<D: ReadAt>(disk: &mut D) -> ExfatResult<Geometry> {
    let mut bs = [0u8; 512];
    disk.read_at(0, &mut bs)?;

    if &bs[3..11] != b"EXFAT   " {
        return Err(ExfatError::Invalid("missing EXFAT signature"));
    }
    if bs[510] != 0x55 || bs[511] != 0xAA {
        return Err(ExfatError::Invalid("missing boot signature"));
    }
    // MustBeZero guards against FAT32 BPBs that happen to carry the name.
    if bs[11..64].iter().any(|&b| b != 0) {
        return Err(ExfatError::Invalid("MustBeZero region is not zero"));
    }

    let bps_shift = bs[108];
    let spc_shift = bs[109];
    if !(9..=12).contains(&bps_shift) {
        return Err(ExfatError::Invalid("BytesPerSectorShift out of range"));
    }
    if spc_shift > 25 - bps_shift {
        return Err(ExfatError::Invalid("SectorsPerClusterShift out of range"));
    }

    let geo = Geometry {
        bytes_per_sector: 1u32 << bps_shift,
        sectors_per_cluster: 1u32 << spc_shift,
        fat_offset_sectors: u32::from_le_bytes(bs[80..84].try_into().unwrap()),
        fat_length_sectors: u32::from_le_bytes(bs[84..88].try_into().unwrap()),
        cluster_heap_offset_sectors: u32::from_le_bytes(bs[88..92].try_into().unwrap()),
        cluster_count: u32::from_le_bytes(bs[92..96].try_into().unwrap()),
        root_first_cluster: u32::from_le_bytes(bs[96..100].try_into().unwrap()),
    };
    if geo.fat_offset_sectors < 24 {
        return Err(ExfatError::Invalid("FatOffset overlaps boot regions"));
    }
    if geo.root_first_cluster < 2 || geo.root_first_cluster >= geo.cluster_count + 2 {
        return Err(ExfatError::Invalid("root cluster out of range"));
    }

    verify_vbr_checksum(disk, geo.bytes_per_sector)?;
    Ok(geo)
}

/// Sectors 0..=10 checksum (skipping VolumeFlags and PercentInUse) must be
/// repeated through sector 11 (spec §3.4).
fn verify_vbr_checksum<D: ReadAt>(disk: &mut D, bps: u32) -> ExfatResult<()> {
    let mut region = vec![0u8; bps as usize * 11];
    disk.read_at(0, &mut region)?;
    let mut checksum: u32 = 0;
    for (i, &b) in region.iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(b as u32);
    }
    let mut sector = vec![0u8; bps as usize];
    disk.read_at(bps as u64 * 11, &mut sector)?;
    for four in sector.chunks_exact(4) {
        if u32::from_le_bytes(four.try_into().unwrap()) != checksum {
            return Err(ExfatError::Invalid("VBR checksum mismatch"));
        }
    }
    Ok(())
}
