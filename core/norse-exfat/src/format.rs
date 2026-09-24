//! exFAT formatter: lay down a fresh, empty exFAT volume (planning doc §7,
//! P5 write side). Produces a volume that `read_boot_region`/`ExfatFs::open`
//! accept and that `fsck.exfat` reports clean, so a new VeraCrypt container
//! can carry exFAT instead of FAT (enabling files larger than 4 GiB).
//!
//! Layout is packed tight (no 1 MiB alignment padding) because the data area
//! of a small hidden volume can be only a few MiB: boot regions, then the
//! FAT, then the cluster heap holding the allocation bitmap, the up-case
//! table, and an empty root directory.
//!
//! Every structure is written explicitly. Over an encrypted device an
//! unwritten sector decrypts to pseudo-random plaintext, so we cannot rely on
//! "zero" backing — the FAT region, the whole allocation bitmap, and the root
//! cluster are each written in full.

use crate::{ExfatError, ExfatResult, WriteAt};

/// Microsoft's canonical compressed up-case table (extracted from a
/// reference `mkfs.exfat` volume). Its checksum is recomputed at format time
/// so the directory entry always matches these bytes.
const UPCASE: &[u8] = &crate::upcase_data::UPCASE_TABLE;

const BPS_SHIFT: u32 = 9;
const BPS: u64 = 1 << BPS_SHIFT; // 512
const BOOT_SECTORS: u64 = 24; // main (0..11) + backup (12..23)

const FAT_MEDIA: u32 = 0xFFFF_FFF8;
const FAT_EOF: u32 = 0xFFFF_FFFF;

fn div_ceil(a: u64, b: u64) -> u64 {
    a.div_ceil(b)
}
fn round_up(a: u64, m: u64) -> u64 {
    div_ceil(a, m) * m
}

/// Cluster-size policy (bytes-per-sector fixed at 512): 4 KiB up to 256 MiB,
/// 32 KiB up to 32 GiB, else 128 KiB — the usual exFAT trade-off between
/// per-cluster slack and FAT/bitmap size.
fn choose_spc_shift(total_bytes: u64) -> u32 {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    if total_bytes <= 256 * MIB {
        3 // 4 KiB
    } else if total_bytes <= 32 * GIB {
        6 // 32 KiB
    } else {
        8 // 128 KiB
    }
}

/// The exFAT checksum used for both the boot region and the up-case table:
/// rotate the accumulator right one bit, add each byte. `skip` names byte
/// indices to ignore (VolumeFlags/PercentInUse for the boot region).
fn rolling_checksum(bytes: &[u8], skip: &[usize]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(b as u32);
    }
    sum
}

/// Format `disk` (already `total_bytes` long) as an empty exFAT volume.
/// `volume_serial` is the volume ID reported to the OS; the caller supplies
/// it (from a random source) so this crate stays dependency-free.
pub fn format<D: WriteAt>(disk: &mut D, total_bytes: u64, volume_serial: u32) -> ExfatResult<()> {
    let total_sectors = total_bytes / BPS;
    let spc_shift = choose_spc_shift(total_bytes);
    let spc: u64 = 1 << spc_shift;
    let cluster_bytes = BPS * spc;

    // FAT starts just after the boot regions, aligned to a cluster boundary so
    // the heap is cluster-aligned. Size the FAT for the largest cluster count
    // the space could hold; the real count is then never larger, so the FAT is
    // always big enough (a few unused entries at the tail are harmless).
    let fat_offset = round_up(BOOT_SECTORS, spc);
    if total_sectors <= fat_offset {
        return Err(ExfatError::Invalid("volume too small for exFAT"));
    }
    let cc_max = (total_sectors - fat_offset) / spc;
    let fat_length = round_up(div_ceil((cc_max + 2) * 4, BPS), spc);
    let heap_offset = fat_offset + fat_length;
    if total_sectors <= heap_offset {
        return Err(ExfatError::Invalid("volume too small for exFAT"));
    }
    let cluster_count = (total_sectors - heap_offset) / spc;

    // Metadata clusters, laid out contiguously from cluster 2.
    let bitmap_bytes = div_ceil(cluster_count, 8);
    let bm_clusters = div_ceil(bitmap_bytes, cluster_bytes);
    let upcase_clusters = div_ceil(UPCASE.len() as u64, cluster_bytes);
    let root_clusters = 1u64;
    let bitmap_first = 2u64;
    let upcase_first = bitmap_first + bm_clusters;
    let root_first = upcase_first + upcase_clusters;
    let used_clusters = bm_clusters + upcase_clusters + root_clusters;
    if cluster_count < used_clusters || root_first + root_clusters > cluster_count + 2 {
        return Err(ExfatError::Invalid("volume too small for exFAT metadata"));
    }

    let cluster_off = |cluster: u64| heap_offset * BPS + (cluster - 2) * cluster_bytes;

    // ---- FAT: entry 0 = media, entry 1 = EOF, then a chain per metadata run.
    let mut fat = vec![0u8; (fat_length * BPS) as usize];
    let set_fat = |fat: &mut [u8], idx: u64, val: u32| {
        let o = (idx * 4) as usize;
        fat[o..o + 4].copy_from_slice(&val.to_le_bytes());
    };
    set_fat(&mut fat, 0, FAT_MEDIA);
    set_fat(&mut fat, 1, FAT_EOF);
    let chain = |fat: &mut [u8], first: u64, n: u64| {
        for i in 0..n {
            let val = if i + 1 == n { FAT_EOF } else { (first + i + 1) as u32 };
            set_fat(fat, first + i, val);
        }
    };
    chain(&mut fat, bitmap_first, bm_clusters);
    chain(&mut fat, upcase_first, upcase_clusters);
    chain(&mut fat, root_first, root_clusters);
    disk.write_at(fat_offset * BPS, &fat)?;

    // ---- Allocation bitmap: mark the metadata clusters used, rest free.
    let mut bitmap = vec![0u8; (bm_clusters * cluster_bytes) as usize];
    for c in 2..(root_first + root_clusters) {
        let bit = (c - 2) as usize;
        bitmap[bit / 8] |= 1 << (bit % 8);
    }
    disk.write_at(cluster_off(bitmap_first), &bitmap)?;

    // ---- Up-case table (canonical bytes), padded to whole clusters.
    let mut upcase = vec![0u8; (upcase_clusters * cluster_bytes) as usize];
    upcase[..UPCASE.len()].copy_from_slice(UPCASE);
    disk.write_at(cluster_off(upcase_first), &upcase)?;
    let upcase_checksum = rolling_checksum(UPCASE, &[]);

    // ---- Root directory: volume label, bitmap entry, up-case entry.
    let mut root = vec![0u8; (root_clusters * cluster_bytes) as usize];
    // 0x83 Volume Label.
    let label: Vec<u16> = "VAULTPONY".encode_utf16().collect();
    root[0] = 0x83;
    root[1] = label.len() as u8;
    for (i, ch) in label.iter().enumerate() {
        root[2 + i * 2..4 + i * 2].copy_from_slice(&ch.to_le_bytes());
    }
    // 0x81 Allocation Bitmap.
    let b = 32;
    root[b] = 0x81;
    root[b + 20..b + 24].copy_from_slice(&(bitmap_first as u32).to_le_bytes());
    root[b + 24..b + 32].copy_from_slice(&bitmap_bytes.to_le_bytes());
    // 0x82 Up-case Table.
    let u = 64;
    root[u] = 0x82;
    root[u + 4..u + 8].copy_from_slice(&upcase_checksum.to_le_bytes());
    root[u + 20..u + 24].copy_from_slice(&(upcase_first as u32).to_le_bytes());
    root[u + 24..u + 32].copy_from_slice(&(UPCASE.len() as u64).to_le_bytes());
    disk.write_at(cluster_off(root_first), &root)?;

    // ---- Boot region (12 sectors), written twice (main + backup copy).
    let percent = ((used_clusters * 100) / cluster_count).min(100) as u8;
    let boot = build_boot_region(
        total_sectors,
        fat_offset,
        fat_length,
        heap_offset,
        cluster_count,
        root_first,
        volume_serial,
        spc_shift,
        percent,
    );
    disk.write_at(0, &boot)?;
    disk.write_at(12 * BPS, &boot)?;

    disk.flush()?;
    Ok(())
}

/// Build the 12-sector main boot region: boot sector, 8 extended boot
/// sectors, OEM parameters, reserved, and the repeated VBR checksum.
#[allow(clippy::too_many_arguments)]
fn build_boot_region(
    total_sectors: u64,
    fat_offset: u64,
    fat_length: u64,
    heap_offset: u64,
    cluster_count: u64,
    root_first: u64,
    volume_serial: u32,
    spc_shift: u32,
    percent_in_use: u8,
) -> Vec<u8> {
    let bps = BPS as usize;
    let mut region = vec![0u8; bps * 12];
    let bs = &mut region[0..bps];

    bs[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]); // JumpBoot
    bs[3..11].copy_from_slice(b"EXFAT   "); // FileSystemName
                                            // 11..64 MustBeZero (already 0)
                                            // 64..72 PartitionOffset = 0
    bs[72..80].copy_from_slice(&total_sectors.to_le_bytes());
    bs[80..84].copy_from_slice(&(fat_offset as u32).to_le_bytes());
    bs[84..88].copy_from_slice(&(fat_length as u32).to_le_bytes());
    bs[88..92].copy_from_slice(&(heap_offset as u32).to_le_bytes());
    bs[92..96].copy_from_slice(&(cluster_count as u32).to_le_bytes());
    bs[96..100].copy_from_slice(&(root_first as u32).to_le_bytes());
    bs[100..104].copy_from_slice(&volume_serial.to_le_bytes());
    bs[104..106].copy_from_slice(&0x0100u16.to_le_bytes()); // FS revision 1.00
                                                            // 106..108 VolumeFlags = 0
    bs[108] = BPS_SHIFT as u8;
    bs[109] = spc_shift as u8;
    bs[110] = 1; // NumberOfFats
    bs[111] = 0x80; // DriveSelect
    bs[112] = percent_in_use;
    // 113..120 Reserved; 120..510 BootCode (all 0)
    bs[510] = 0x55;
    bs[511] = 0xAA;

    // Extended boot sectors 1..=8: zero but for the trailing signature.
    for s in 1..=8 {
        let sec = &mut region[s * bps..(s + 1) * bps];
        sec[bps - 4..bps].copy_from_slice(&[0x00, 0x00, 0x55, 0xAA]);
    }
    // Sector 9 (OEM parameters) and 10 (reserved) stay zero.

    // Sector 11: the VBR checksum over sectors 0..=10, repeated to fill.
    let checksum = rolling_checksum(&region[0..bps * 11], &[106, 107, 112]);
    let csec = &mut region[bps * 11..bps * 12];
    for four in csec.chunks_exact_mut(4) {
        four.copy_from_slice(&checksum.to_le_bytes());
    }
    region
}
