//! 2.0.0 (issues #5 and #6): the unlock "Hash" menu. Picking the hash a
//! volume uses opens it after deriving with that hash only; picking any
//! other fails with the ordinary wrong-password error, after the same
//! number of derivations for every container (so timing still says nothing
//! about a hidden volume).

use vault_core::{ContainerFs, Session};
use vc_format::{CreateParams, UnlockSecret};
use vc_io::FileDevice;
use vc_types::{KdfFilter, VcError};

// PIM 1 keeps derivations cheap; VeraCrypt then wants 20+ characters.
const PW: &[u8] = b"hash-filter-gate-password-01";

fn prf(name: &str) -> &'static vc_types::Prf {
    vc_types::registry::PRFS
        .iter()
        .find(|p| p.name == name)
        .unwrap()
}

fn make(prf_name: &str, scheme: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "vaultpony-hash-{}-{}.vc",
        prf_name.replace('/', "_"),
        std::process::id()
    ));
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(4 << 20).unwrap();
    drop(f);
    let params = CreateParams {
        scheme: vc_types::registry::scheme_by_name(scheme).unwrap(),
        prf: prf(prf_name),
        pim: 1,
        passphrase: PW,
        keyfiles: &[],
        size: 4 << 20,
        sector_size: 512,
    };
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &params,
        ContainerFs::Fat,
    )
    .unwrap();
    path
}

fn unlock(path: &std::path::Path, kdf: KdfFilter) -> (Result<Session, VcError>, usize) {
    let mut steps = 0usize;
    let r = Session::unlock_device_with(
        Box::new(FileDevice::open_rw(path).unwrap()),
        &UnlockSecret {
            kdf,
            ..UnlockSecret::new(PW, 1)
        },
        &mut |_, _, _| steps += 1,
    );
    (r, steps)
}

#[test]
fn each_hash_opens_only_its_own_volumes() {
    for (filter, name) in KdfFilter::SINGLE {
        let path = make(name, "Camellia-Kuznyechik");
        let (ok, _) = unlock(&path, filter);
        let s = ok.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(s.prf(), name);
        assert_eq!(s.scheme(), "Camellia(Kuznyechik)");
        drop(s);

        for (other, other_name) in KdfFilter::SINGLE {
            if other == filter {
                continue;
            }
            let (r, steps) = unlock(&path, other);
            assert!(
                matches!(r, Err(VcError::NotFoundOrWrongPassword)),
                "{name} opened with {other_name}"
            );
            // One derivation per header position, the same for every
            // container whatever it holds.
            assert_eq!(steps, 4, "{other_name} on {name}");
        }
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn hash_names_and_cascades_round_trip_through_the_registry() {
    let path = make("Whirlpool", "AES-Twofish-Serpent");
    let (s, steps) = unlock(&path, KdfFilter::Whirlpool);
    let s = s.unwrap();
    assert_eq!(steps, 1);
    let scheme = vc_types::registry::scheme_by_name(s.scheme()).unwrap();
    assert_eq!(scheme.display_name(), "AES-Twofish-Serpent");
    std::fs::remove_file(&path).ok();
}

/// The same against containers made by VeraCrypt itself (skipped without
/// the fixture corpus).
#[test]
fn veracrypt_fixtures_open_with_their_hash_only() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let cases = [
        (
            "aes-sha_512-fat-512-pim0-plain.vc",
            &b"vaultpony-fixture"[..],
            0u32,
            KdfFilter::Sha512,
            KdfFilter::Streebog,
        ),
        (
            "aes-argon2id-fat-512-pim1-plain.vc",
            &b"vaultpony-fixture-argon2"[..],
            1,
            KdfFilter::Argon2idOnly,
            KdfFilter::Sha512,
        ),
    ];
    for (file, pw, pim, right, wrong) in cases {
        let path = dir.join(file);
        if !path.exists() {
            eprintln!("SKIP: fixture corpus not present ({file})");
            return;
        }
        let open = |kdf| {
            Session::unlock_device_with(
                Box::new(FileDevice::open_read(&path).unwrap()),
                &UnlockSecret {
                    kdf,
                    ..UnlockSecret::new(pw, pim)
                },
                &mut |_, _, _| {},
            )
        };
        assert!(open(right).is_ok(), "{file}");
        assert!(
            matches!(open(wrong), Err(VcError::NotFoundOrWrongPassword)),
            "{file}"
        );
    }
}
