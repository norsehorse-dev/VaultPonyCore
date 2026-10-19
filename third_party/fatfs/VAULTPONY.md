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

## Removal condition

Delete this directory and the `[patch.crates-io]` entry when a fatfs
release ≥ 0.4 containing the dot-entry fix is published and the 0.4 API
migration is done. Discovered by the P4 differential gate (fsck.fat over a
VeraCrypt-decrypted image); a regression test exists in
core/vault-core/tests/write_gate.rs.
