# Vendored fatfs 0.3.6 — why this copy exists

Vendored from crates.io `fatfs 0.3.6` (MIT, © Rafał Harabień — see
LICENSE.txt) and applied via `[patch.crates-io]` in the workspace root.

## Local changes

1. `src/dir.rs`, `write_entry`: the special `.` and `..` directory entries
   are written as bare 8.3 entries with no LFN records. Stock 0.3.6 emits
   LFN entries for them, which `fsck.fat` flags ("Start does point to
   containing directory" after renaming the orphaned record) and Windows
   treats as directory corruption. Upstream fixed this on master
   (unreleased as of vendoring); our patch mirrors that fix's behavior.

2. `src/fs.rs`: new public `FileSystem::stats_recounted()`, which recounts
   free clusters from the FAT (the existing private `recalc_free_clusters`)
   rather than trusting the FSInfo hint. FSInfo's free count is advisory and
   can be stale on volumes another OS left dirty; VaultPony shows free space
   and pre-flights imports against it, so it counts once per session and
   relies on fatfs's own bookkeeping after that. FSInfo is only marked dirty
   when the recount differs from the stored hint, so viewing free space never
   rewrites an accurate FSInfo sector.

3. `src/fs.rs`: new public `FileSystem::sync_metadata()`, which writes the
   FSInfo sector (if changed) and clears the volume dirty flag without
   unmounting. VaultPony calls it on every flush, so FSInfo is current at the
   end of each logical operation. With two sessions on one volume (the iOS app
   and its File Provider extension, 2.0.0 rc3), the one that remounts must not
   later write a stale FSInfo over the other's.

4. `src/dir_entry.rs`: directory entries (8.3 and LFN) are serialized into a
   32-byte buffer and written with one write. Stock 0.3.6 writes each field
   separately, so a power cut or process kill in the middle of writing an
   entry into a deleted slot could leave the new name next to the old entry's
   first cluster, cross-linking it with a live file (fsck.fat: "share
   clusters", then truncates the live file). Found by running the FAT
   power-loss harness with fsck at every cut
   (`VAULTPONY_FULL_POWERLOSS=1`).

5. `src/fs.rs`: new public `FileSystem::release_without_writing()`. After
   it, dropping the filesystem writes nothing (no FSInfo, no dirty flag).
   Used when a session remounts because another process changed the volume:
   the old instance's cached FSInfo is stale by then and must not overwrite
   the other process's.

6. `src/file.rs`, `write`: a new cluster for the FAT32 root directory is
   zeroed. Stock 0.3.6 zeroes a new cluster only when `is_dir()` is true,
   and that reads the file's own directory entry, which the FAT32 root does
   not have. Its new clusters were left as they were on disk. Inside an
   encrypted container that is noise, so once the vault's top folder grew
   past its first cluster it listed hundreds of junk files and folders, and
   every later file needed another cluster because the junk left no free
   run of entries. Subdirectories and FAT12/16 roots (a fixed area) were
   never affected. Found while measuring import speed for 2.1.0; regression
   test in core/vc-fs/tests/fat_root_growth.rs.
   `FsOptions::legacy_unzeroed_root(true)` brings the old behavior back for
   one filesystem instance. It exists so tests can build a volume damaged
   the old way (core/vc-fs/tests/fat_root_repair.rs); nothing else sets it.
   Vaults already damaged are repaired at mount by `vc_fs::fat_repair`.

## Removal condition

Delete this directory and the `[patch.crates-io]` entry when a fatfs
release ≥ 0.4 containing the dot-entry fix is published and the 0.4 API
migration is done. Discovered by the P4 differential gate (fsck.fat over a
VeraCrypt-decrypted image); a regression test exists in
core/vault-core/tests/write_gate.rs.
