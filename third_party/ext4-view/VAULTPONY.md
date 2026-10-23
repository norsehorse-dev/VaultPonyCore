# Vendored ext4-view 1.0.0, and why this copy exists

Vendored from crates.io `ext4-view 1.0.0` (Apache-2.0 OR MIT, Google LLC;
see LICENSE-APACHE and LICENSE-MIT) and applied via `[patch.crates-io]` in
the workspace root. VaultPony reads ext4 volumes through it, read-only
(2.0.0, plan 6.3).

## Local changes

1. `src/iters/file_blocks/block_map.rs`, `IndirectBlockIter::new`: an
   indirect, double-indirect or triple-indirect pointer of zero is a hole
   that covers every block under it. Stock 1.0.0 reads block 0 as if it were
   a table and fails the read with "invalid read ... from block 0", so any
   sparse file on ext2 or ext3 (block-mapped, not extent-mapped) whose hole
   spans a whole indirect range can't be read. The patch uses an all-zero
   table instead, which yields a hole for each entry. Extent-mapped files
   (every ext4 default) never take this path. Covered by
   `core/vault-core/tests/ext4_gate.rs` (the ext2 and ext3 cases read a
   sparse file across the double-indirect range).

Drop this copy when an upstream release carries the same fix.
