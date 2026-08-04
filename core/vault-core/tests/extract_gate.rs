//! The extraction gate (doc §12, P0 and beyond): for every *populated*
//! fixture in the manifest, every file in its known plaintext tree reads
//! back byte-identical through the full stack — candidate search → header
//! decrypt → XTS data path → filesystem adapter — verified against the
//! sha256 tree the reference tooling recorded.
//!
//! As filesystems land (FAT in P2, exFAT read here, NTFS next) their
//! fixtures join this gate automatically: it sweeps whatever the manifest
//! marks as populated.

use sha2::{Digest, Sha256};
use std::path::PathBuf;

const PASSWORD: &[u8] = b"vaultpony-fixture";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

#[test]
fn extraction_gate_every_populated_fixture_reads_byte_identical() {
    let dir = fixtures_dir();
    let manifest_path = dir.join("manifest.json");
    if !manifest_path.exists() {
        eprintln!("SKIP: fixture corpus not present");
        return;
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();

    let mut verified_fixtures = 0usize;
    for (id, entry) in manifest["fixtures"].as_object().unwrap() {
        if entry["status"] != "ok" {
            continue;
        }
        let Some(tree) = entry["tree"].as_object() else {
            continue; // unpopulated (corpus-only) fixture
        };
        let container = dir.join(format!("{id}.vc"));
        if !container.exists() {
            continue;
        }
        let pim = entry["params"]["pim"].as_u64().unwrap_or(0) as u32;

        let mut session = vault_core::Session::unlock(&container, PASSWORD, pim, &mut |_, _, _| {})
            .unwrap_or_else(|e| panic!("{id}: unlock: {e}"));
        let vfs = session.vfs();

        for (rel, want) in tree {
            let want_hex = want.as_str().unwrap();
            let st = vfs
                .stat(rel)
                .unwrap_or_else(|e| panic!("{id}/{rel}: stat: {e}"));
            assert!(!st.is_dir, "{id}/{rel} should be a file");

            let mut hasher = Sha256::new();
            let mut offset = 0u64;
            let mut buf = vec![0u8; 256 * 1024];
            let mut total = 0u64;
            loop {
                let n = vfs
                    .read_at(rel, offset, &mut buf)
                    .unwrap_or_else(|e| panic!("{id}/{rel}: read: {e}"));
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                offset += n as u64;
                total += n as u64;
            }
            assert_eq!(total, st.size, "{id}/{rel}: read length vs stat size");
            let got_hex = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(&got_hex, want_hex, "{id}/{rel}: content mismatch");
        }

        // Listing sanity on the root.
        let names: Vec<String> = vfs.list("/").unwrap().into_iter().map(|e| e.name).collect();
        assert!(
            names.contains(&"readme.txt".to_string()),
            "{id}: root listing missing readme.txt"
        );
        session.lock();
        verified_fixtures += 1;
    }
    eprintln!("extraction gate: {verified_fixtures} populated fixture(s) verified");
    assert!(
        verified_fixtures > 0,
        "manifest present but nothing verified"
    );
}
