# VaultPonyCore

The shared Rust core for VaultPony: open and edit VeraCrypt file containers with
zero network access. One core, byte-faithful VeraCrypt compatibility, consumed
by the platform apps (VaultPonyAndroid, with iOS and desktop to follow).

VeraCrypt is a registered trademark of IDRIX. VaultPony is not affiliated with
or endorsed by IDRIX. This is a clean-room implementation from published format
documentation and independent crates; no VeraCrypt or TrueCrypt source is used
or linked.

## Layout

| Path | What |
|---|---|
| core/vc-types | Header layout, cipher/PRF registry (generated), geometry, errors |
| core/vc-format | Header discovery, candidate search, decrypt/validate, backup headers |
| core/vc-crypto | PBKDF2 header-key derivation, XTS engine including cascades |
| core/vc-io | Block-device trait: std::fs file (desktop) and raw-fd (mobile) |
| core/vc-fs | VFS trait and adapters: fatfs (RW), norse-exfat, ntfs (RO) |
| core/norse-exfat | Our exFAT implementation |
| core/vault-core | Sessions, unlock flow, mount table, auto-lock |
| core/vault-ffi | UniFFI boundary to Kotlin and Swift bindings |
| core/vaultpony-cli | Headless CLI; doubles as test harness and support tool |
| tools/gen-fixtures | Matrix generator and fixture corpus builder |

third_party/fatfs is a patched vendor copy (MIT; see its VAULTPONY.md for why,
and when it is removed).

## Build

    cargo test --workspace --locked

The toolchain is pinned in rust-toolchain.toml, Cargo.lock is committed, and CI
and release builds always use --locked.

Generate mobile bindings:

    cargo build -p vault-ffi
    cargo run -p vault-ffi --features cli --bin uniffi-bindgen -- generate --library target/debug/libvault_ffi.so --language kotlin --language swift --out-dir bindings/

## Principles

Fixtures are the spec: the compatibility corpus is generated from a pinned
VeraCrypt source checkout by tools/gen-fixtures/gen_matrix.py, never hand-edited.
Prose loses to fixtures. Secrets are zeroized after use and copies are kept
minimal; see THREAT_MODEL.md for the full security posture.

## License

Apache-2.0. See LICENSE.
