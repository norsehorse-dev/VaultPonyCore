//! Directory entry sets (exFAT spec §6): 32-byte entries; a File primary
//! entry (0x85) followed by a Stream Extension (0xC0) and File Name (0xC1)
//! secondaries, covered by a rotate-right set checksum. Sets may span
//! cluster boundaries; entry type 0x00 ends the directory.

use crate::boot::Geometry;
use crate::{Entry, ExfatError, ExfatResult, ReadAt};

pub const ENTRY_END: u8 = 0x00;
pub const ENTRY_BITMAP: u8 = 0x81;
pub const ENTRY_UPCASE: u8 = 0x82;
pub const ENTRY_LABEL: u8 = 0x83;
pub const ENTRY_FILE: u8 = 0x85;
pub const ENTRY_STREAM: u8 = 0xC0;
pub const ENTRY_NAME: u8 = 0xC1;

const ATTR_DIRECTORY: u16 = 0x0010;

/// Walk a directory's raw 32-byte entries in order, following its cluster
/// chain (or arithmetic run when `no_fat_chain`). The callback returns
/// `Ok(false)` to stop early. `data_len` bounds the walk for directories
/// whose stream entry records a size; pass `u64::MAX` for the root.
pub fn walk_raw_entries<D: ReadAt>(
    disk: &mut D,
    geo: &Geometry,
    first_cluster: u32,
    no_fat_chain: bool,
    data_len: u64,
    mut f: impl FnMut(&[u8; 32]) -> ExfatResult<bool>,
) -> ExfatResult<()> {
    if first_cluster == 0 {
        return Ok(()); // empty directory with no allocation
    }
    let cluster_bytes = geo.cluster_bytes();
    // For a FAT-chained directory we read the FAT (bounded by real disk reads).
    // For a NoFatChain run the cluster count comes from an unauthenticated
    // stream entry, so we must never materialize it: a corrupt or crafted size
    // (up to u64::MAX) would request an enormous Vec and abort the process. We
    // iterate the contiguous run lazily instead, capped at the volume's cluster
    // count, and let each cluster's own bounds check stop a run that overruns.
    let fat_chain: Vec<u32> = if no_fat_chain {
        Vec::new()
    } else {
        crate::fat::read_chain(disk, geo, first_cluster, None)?
    };
    let run_len: u64 = if no_fat_chain {
        data_len
            .div_ceil(cluster_bytes)
            .max(1)
            .min(geo.cluster_count as u64)
    } else {
        fat_chain.len() as u64
    };

    let mut cluster_buf = vec![0u8; cluster_bytes as usize];
    let mut seen: u64 = 0;
    let mut idx: u64 = 0;
    while idx < run_len {
        if seen >= data_len {
            return Ok(());
        }
        let cluster = if no_fat_chain {
            match u32::try_from(idx).ok().and_then(|d| first_cluster.checked_add(d)) {
                Some(c) => c,
                None => return Ok(()), // ran past the addressable cluster space
            }
        } else {
            fat_chain[idx as usize]
        };
        idx += 1;
        disk.read_at(geo.cluster_offset(cluster)?, &mut cluster_buf)?;
        for raw in cluster_buf.chunks_exact(32) {
            if seen >= data_len {
                return Ok(());
            }
            seen += 32;
            let raw: &[u8; 32] = raw.try_into().unwrap();
            if raw[0] == ENTRY_END {
                return Ok(());
            }
            if !f(raw)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Entry-set checksum (spec §6.3.3): 16-bit rotate-right over all bytes of
/// the set, skipping the SetChecksum field itself (bytes 2..4 of entry 0).
fn set_checksum(entries: &[[u8; 32]]) -> u16 {
    let mut cs: u16 = 0;
    for (idx, e) in entries.iter().enumerate() {
        for (i, &b) in e.iter().enumerate() {
            if idx == 0 && (i == 2 || i == 3) {
                continue;
            }
            cs = cs.rotate_right(1).wrapping_add(b as u16);
        }
    }
    cs
}

/// exFAT timestamp (spec §7.4.8) → Unix millis. `utc_offset` is in 15-min
/// units with bit 7 as the validity flag.
fn timestamp_ms(ts: u32, centis: u8, utc_offset: u8) -> Option<i64> {
    let year = 1980 + (ts >> 25) as i64;
    let month = ((ts >> 21) & 0xF) as i64;
    let day = ((ts >> 16) & 0x1F) as i64;
    let hour = ((ts >> 11) & 0x1F) as i64;
    let min = ((ts >> 5) & 0x3F) as i64;
    let sec = ((ts & 0x1F) * 2) as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days-from-civil (Howard Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let mut ms = (days * 86400 + hour * 3600 + min * 60 + sec) * 1000 + centis as i64 * 10;
    if utc_offset & 0x80 != 0 {
        let quarter_hours = (utc_offset & 0x7F) as i8 as i64; // sign-extend 7-bit
        let quarter_hours = if quarter_hours >= 64 {
            quarter_hours - 128
        } else {
            quarter_hours
        };
        ms -= quarter_hours * 15 * 60 * 1000;
    }
    Some(ms)
}

/// Read a directory into entries, validating each set's checksum.
pub fn read_directory<D: ReadAt>(
    disk: &mut D,
    geo: &Geometry,
    first_cluster: u32,
    no_fat_chain: bool,
    data_len: u64,
) -> ExfatResult<Vec<Entry>> {
    // Collect raw entries first (walk borrows the disk).
    let mut raw_entries: Vec<[u8; 32]> = Vec::new();
    walk_raw_entries(disk, geo, first_cluster, no_fat_chain, data_len, |raw| {
        raw_entries.push(*raw);
        Ok(true)
    })?;

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw_entries.len() {
        let raw = &raw_entries[i];
        if raw[0] != ENTRY_FILE {
            i += 1; // system entries, deleted entries (bit 7 clear), labels
            continue;
        }
        let secondary_count = raw[1] as usize;
        // Need the primary entry plus `secondary_count` following entries.
        if secondary_count < 2 || i + 1 + secondary_count > raw_entries.len() {
            return Err(ExfatError::Invalid("file entry set truncated"));
        }
        let set = &raw_entries[i..i + 1 + secondary_count];
        let stored = u16::from_le_bytes([set[0][2], set[0][3]]);
        if set_checksum(set) != stored {
            return Err(ExfatError::Invalid("entry set checksum mismatch"));
        }
        let stream = &set[1];
        if stream[0] != ENTRY_STREAM {
            return Err(ExfatError::Invalid("first secondary is not a stream entry"));
        }

        let attrs = u16::from_le_bytes([set[0][4], set[0][5]]);
        let mtime = u32::from_le_bytes(set[0][12..16].try_into().unwrap());
        let mtime_centis = set[0][22];
        let mtime_utc = set[0][24];

        let flags = stream[1];
        let name_len = stream[3] as usize;
        let valid_size = u64::from_le_bytes(stream[8..16].try_into().unwrap());
        let first = u32::from_le_bytes(stream[20..24].try_into().unwrap());
        let size = u64::from_le_bytes(stream[24..32].try_into().unwrap());

        let mut units: Vec<u16> = Vec::with_capacity(name_len);
        for name_entry in &set[2..] {
            if name_entry[0] != ENTRY_NAME {
                break;
            }
            for c in name_entry[2..32].chunks_exact(2) {
                if units.len() < name_len {
                    units.push(u16::from_le_bytes([c[0], c[1]]));
                }
            }
        }
        if units.len() < name_len {
            return Err(ExfatError::Invalid(
                "file name entries shorter than NameLength",
            ));
        }

        out.push(Entry {
            name: String::from_utf16_lossy(&units),
            is_dir: attrs & ATTR_DIRECTORY != 0,
            size,
            valid_size,
            first_cluster: first,
            no_fat_chain: flags & 0x02 != 0,
            mtime_ms: timestamp_ms(mtime, mtime_centis, mtime_utc),
        });
        i += 1 + secondary_count;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_skips_its_own_field() {
        let mut set = [[0u8; 32]; 2];
        set[0][0] = ENTRY_FILE;
        set[1][0] = ENTRY_STREAM;
        let a = set_checksum(&set);
        set[0][2] = 0xAB;
        set[0][3] = 0xCD;
        assert_eq!(a, set_checksum(&set));
        set[1][5] = 1;
        assert_ne!(a, set_checksum(&set));
    }

    #[test]
    fn timestamp_epoch_math() {
        // 2026-08-02 12:00:00, no offset recorded.
        let ts = ((2026 - 1980) << 25) | (8 << 21) | (2 << 16) | (12 << 11);
        let ms = timestamp_ms(ts, 0, 0).unwrap();
        assert_eq!(ms, 1_785_672_000_000);
    }
}
