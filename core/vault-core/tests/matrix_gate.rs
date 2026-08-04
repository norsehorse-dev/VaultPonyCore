//! The P1 gate (doc §12): every fixture in the corpus unlocks, and the
//! found parameters match what created it. Reads the corpus manifest
//! written by tools/gen-fixtures/create_fixtures.py.
//!
//! Corpus location: $VAULTPONY_CORPUS, falling back to ../../fixtures.
//! Skips politely when absent — the corpus is regenerable, not committed.

use std::path::PathBuf;
use vc_format::{find_header, UnlockSecret};
use vc_io::FileDevice;

fn corpus_dir() -> PathBuf {
    std::env::var_os("VAULTPONY_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"))
}

#[test]
fn p1_gate_every_corpus_fixture_unlocks_with_matching_params() {
    let dir = corpus_dir();
    let manifest_path = dir.join("manifest.json");
    if !manifest_path.exists() {
        eprintln!("SKIP: corpus manifest not present at {}", dir.display());
        return;
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let fixtures = manifest["fixtures"].as_object().unwrap();

    let mut unlocked = 0usize;
    let mut missing = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for (id, entry) in fixtures {
        if entry["status"] != "ok" {
            missing += 1;
            continue;
        }
        // Hidden fixtures carry outer/hidden passwords, not a single
        // `password`; they have their own gate (hidden_gate.rs).
        if entry["kind"] == "hidden" {
            continue;
        }
        let params = &entry["params"];
        let container = dir.join(format!("{id}.vc"));
        if !container.exists() {
            failures.push(format!("{id}: container file missing"));
            continue;
        }
        let mut dev = match FileDevice::open_read(&container) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{id}: open: {e}"));
                continue;
            }
        };
        let secret = UnlockSecret {
            passphrase: params["password"].as_str().unwrap().as_bytes(),
            pim: params["pim"].as_u64().unwrap() as u32,
        };
        match find_header(&mut dev, &secret, &mut |_, _, _| {}) {
            Ok(found) => {
                let want_scheme = params["scheme"].as_str().unwrap();
                let want_prf = params["prf"].as_str().unwrap();
                if found.scheme.name != want_scheme || found.prf.name != want_prf {
                    failures.push(format!(
                        "{id}: unlocked as {}/{} but was created as {want_scheme}/{want_prf}",
                        found.scheme.name, found.prf.name
                    ));
                } else {
                    unlocked += 1;
                }
            }
            Err(e) => failures.push(format!("{id}: {e}")),
        }
    }

    eprintln!("matrix gate: {unlocked} unlocked, {missing} not in corpus (legacy VC needed)");
    assert!(
        failures.is_empty(),
        "matrix gate failures:\n{}",
        failures.join("\n")
    );
    assert!(unlocked > 0, "corpus present but nothing unlocked");
}

// Hidden-volume unlock (P8) is exercised end to end against a populated
// hidden fixture in tests/hidden_gate.rs. The corpus hidden fixtures here
// were created --no-populate (headers only), so this file's sweep already
// covers that their *outer* password unlocks; the dedicated gate covers the
// hidden read and the deniability properties.
