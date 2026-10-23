//! rc3 gate: key handoff to a second process, and two sessions writing one
//! volume (the iOS app and its File Provider extension).
//!
//! Self-contained: every container is created here, so the gate runs without
//! the fixture corpus. "Second process" is a second session over its own
//! file handle, which is exactly what the extension gets (its own fd plus the
//! blob).

use std::path::{Path, PathBuf};
use std::process::Command;
use vault_core::{ContainerFs, Session};
use vc_format::{CreateParams, DecryptedDevice, UnlockSecret};
use vc_io::{BlockDevice, FileDevice};
use vc_types::{KdfFilter, VcError};

// PIM 1 keeps PBKDF2 cheap in debug builds; VeraCrypt then wants 20+ chars.
const PW: &[u8] = b"handoff-gate-password-0001";
const HIDDEN_PW: &[u8] = b"handoff-gate-hidden-pass-0002";
const PIM: u32 = 1;
const SIZE: u64 = 8 << 20;

fn scheme(name: &str) -> &'static vc_types::EncryptionScheme {
    vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == name)
        .unwrap()
}

fn sha512() -> &'static vc_types::Prf {
    &vc_types::registry::PRFS[0]
}

fn params<'a>(scheme_name: &str, pw: &'a [u8]) -> CreateParams<'a> {
    CreateParams {
        scheme: scheme(scheme_name),
        prf: sha512(),
        pim: PIM,
        passphrase: pw,
        keyfiles: &[],
        size: SIZE,
        sector_size: 512,
    }
}

fn tmp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vaultpony-handoff-{tag}-{}.vc", std::process::id()))
}

fn sized_file(path: &Path) {
    let f = std::fs::File::create(path).unwrap();
    f.set_len(SIZE).unwrap();
}

fn make(tag: &str, scheme_name: &str, fs: ContainerFs) -> PathBuf {
    let path = tmp(tag);
    sized_file(&path);
    let dev = FileDevice::open_rw(&path).unwrap();
    vault_core::create_container(Box::new(dev), &params(scheme_name, PW), fs).unwrap();
    path
}

fn secret(pw: &[u8]) -> UnlockSecret<'_> {
    UnlockSecret {
        kdf: KdfFilter::Pbkdf2Only,
        ..UnlockSecret::new(pw, PIM)
    }
}

fn unlock(path: &Path, pw: &[u8]) -> Session {
    let dev = FileDevice::open_rw(path).unwrap();
    Session::unlock_device_with(Box::new(dev), &secret(pw), &mut |_, _, _| {}).unwrap()
}

/// What the extension does: its own handle to the file, plus the blob.
fn import(path: &Path, blob: &[u8]) -> Result<Session, VcError> {
    let dev = FileDevice::open_rw(path).unwrap();
    Session::import_handoff(Box::new(dev), blob)
}

fn write_file(s: &mut Session, path: &str, data: &[u8]) {
    let vfs = s.vfs();
    if vfs.stat(path).is_err() {
        vfs.create(path).unwrap();
    }
    vfs.truncate(path, 0).unwrap();
    vfs.write_at(path, 0, data).unwrap();
    vfs.flush().unwrap();
}

fn read_file(s: &mut Session, path: &str) -> Vec<u8> {
    let size = s.vfs().stat(path).unwrap().size as usize;
    let mut buf = vec![0u8; size];
    let n = s.vfs().read_at(path, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn names(s: &mut Session, dir: &str) -> Vec<String> {
    let mut v: Vec<String> = s
        .vfs()
        .list(dir)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    v.sort();
    v
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Decrypt the data area to a plain image and run the platform fsck on it
/// (skipped when the tool is missing).
fn fsck(container: &Path, pw: &[u8], fs: ContainerFs) {
    if let Some((ok, report)) = fsck_report(container, pw, fs) {
        assert!(ok, "fsck found problems:\n{report}");
    }
}

/// fsck's verdict and output; None when the tool is missing.
fn fsck_report(container: &Path, pw: &[u8], fs: ContainerFs) -> Option<(bool, String)> {
    let tool = match fs {
        ContainerFs::Fat => "fsck.fat",
        ContainerFs::Exfat => "fsck.exfat",
    };
    if Command::new(tool).arg("--help").output().is_err() {
        eprintln!("SKIP fsck: {tool} not installed");
        return None;
    }
    let mut dev = FileDevice::open_read(container).unwrap();
    let found = vc_format::find_header(&mut dev, &secret(pw), &mut |_, _, _| {}).unwrap();
    let geometry = found.header.geometry;
    let xts = vc_crypto::SchemeXts::new(
        found.scheme,
        &found.header.master_keys[..found.scheme.key_bytes()],
    )
    .unwrap();
    let mut decrypted = DecryptedDevice::new(Box::new(dev), xts, &geometry);
    let mut img = vec![0u8; decrypted.len().unwrap() as usize];
    decrypted.read_at(0, &mut img).unwrap();
    let img_path = container.with_extension("img");
    std::fs::write(&img_path, img).unwrap();
    let out = Command::new(tool)
        .arg("-n")
        .arg(&img_path)
        .output()
        .unwrap();
    std::fs::remove_file(&img_path).ok();
    Some((
        out.status.success(),
        format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

#[test]
fn handoff_round_trip_reads_and_writes() {
    vault_core::enable_handoff(true);
    for (i, (scheme_name, fs)) in [
        ("AES", ContainerFs::Fat),
        ("AES", ContainerFs::Exfat),
        ("Serpent(Twofish(AES))", ContainerFs::Fat),
        ("Kuznyechik(Serpent(Camellia))", ContainerFs::Exfat),
    ]
    .into_iter()
    .enumerate()
    {
        let path = make(&format!("rt{i}"), scheme_name, fs);
        let mut app = unlock(&path, PW);
        write_file(&mut app, "/from-app.txt", b"written by the app");
        let blob = app.export_handoff().unwrap();
        // Keys are in there, the password is not.
        assert!(!blob.windows(PW.len()).any(|w| w == PW));

        let mut ext = import(&path, &blob).unwrap();
        assert_eq!(ext.scheme(), scheme_name);
        assert_eq!(ext.prf(), "SHA-512");
        assert!(!ext.is_hidden());
        assert_eq!(read_file(&mut ext, "/from-app.txt"), b"written by the app");
        write_file(&mut ext, "/from-ext.bin", &payload(7, 70_000));
        ext.lock();

        app.remount().unwrap();
        assert_eq!(read_file(&mut app, "/from-ext.bin"), payload(7, 70_000));
        app.lock();

        let mut fresh = unlock(&path, PW);
        assert_eq!(names(&mut fresh, "/"), vec!["from-app.txt", "from-ext.bin"]);
        fresh.lock();
        fsck(&path, PW, fs);
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn handoff_refuses_another_container() {
    vault_core::enable_handoff(true);
    let a = make("other-a", "AES", ContainerFs::Fat);
    let b = make("other-b", "AES", ContainerFs::Fat);
    let blob = unlock(&a, PW).export_handoff().unwrap();
    assert!(matches!(
        import(&b, &blob),
        Err(VcError::NotFoundOrWrongPassword)
    ));
    // Same file after its header was rewritten (password change): refused.
    {
        let mut dev = FileDevice::open_rw(&a).unwrap();
        vault_core::change_password_with(
            &mut dev,
            &secret(PW),
            &secret(b"handoff-gate-new-password-03"),
        )
        .unwrap();
    }
    assert!(matches!(
        import(&a, &blob),
        Err(VcError::NotFoundOrWrongPassword)
    ));
    std::fs::remove_file(&a).ok();
    std::fs::remove_file(&b).ok();
}

#[test]
fn malformed_blobs_fail_cleanly() {
    vault_core::enable_handoff(true);
    let path = make("malformed", "AES", ContainerFs::Fat);
    let blob = unlock(&path, PW).export_handoff().unwrap();
    // Every truncation, and a flipped byte in each header field, is refused
    // without a panic.
    for cut in 0..blob.len() {
        assert!(import(&path, &blob[..cut]).is_err(), "truncated at {cut}");
    }
    let mut longer = blob.to_vec();
    longer.push(0);
    assert!(import(&path, &longer).is_err());
    for i in [0usize, 3, 4, 5, 6] {
        let mut bad = blob.to_vec();
        bad[i] ^= 0x5a;
        assert!(import(&path, &bad).is_err(), "byte {i}");
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn hidden_volume_handoff_opens_the_hidden_volume() {
    vault_core::enable_handoff(true);
    let path = tmp("hidden");
    sized_file(&path);
    vault_core::create_container_with_hidden(
        || Ok(Box::new(FileDevice::open_rw(&path)?) as Box<dyn BlockDevice>),
        &params("AES", PW),
        &params("AES", HIDDEN_PW),
        2 << 20,
        ContainerFs::Fat,
    )
    .unwrap();
    let mut app = unlock(&path, HIDDEN_PW);
    assert!(app.is_hidden());
    write_file(&mut app, "/hidden.txt", b"inside the hidden volume");
    let blob = app.export_handoff().unwrap();
    let mut ext = import(&path, &blob).unwrap();
    assert!(ext.is_hidden());
    assert_eq!(
        read_file(&mut ext, "/hidden.txt"),
        b"inside the hidden volume"
    );
    ext.lock();
    app.lock();
    // The outer volume never sees it.
    let mut outer = unlock(&path, PW);
    assert!(outer.vfs().stat("/hidden.txt").is_err());
    std::fs::remove_file(&path).ok();
}

#[test]
fn protected_outer_handoff_keeps_protection_and_the_latch() {
    vault_core::enable_handoff(true);
    let path = tmp("protect");
    sized_file(&path);
    vault_core::create_container_with_hidden(
        || Ok(Box::new(FileDevice::open_rw(&path)?) as Box<dyn BlockDevice>),
        &params("AES", PW),
        &params("AES", HIDDEN_PW),
        4 << 20,
        ContainerFs::Fat,
    )
    .unwrap();
    let mut app = Session::unlock_outer_protected_device_with(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &secret(PW),
        HIDDEN_PW,
        &mut |_, _, _| {},
    )
    .unwrap();
    assert!(app.is_outer_protected());
    write_file(&mut app, "/small.txt", b"fits in the outer free space");

    // Protection carries over: the extension can't overrun the hidden area.
    let blob = app.export_handoff().unwrap();
    let mut ext = import(&path, &blob).unwrap();
    assert!(ext.is_outer_protected());
    assert!(!ext.is_hidden());
    ext.vfs().create("/big.bin").unwrap();
    let chunk = payload(3, 256 * 1024);
    let mut tripped = false;
    for i in 0..40u64 {
        match ext
            .vfs()
            .write_at("/big.bin", i * chunk.len() as u64, &chunk)
        {
            Ok(_) => {}
            Err(VcError::HiddenVolumeProtected) => {
                tripped = true;
                break;
            }
            Err(VcError::Filesystem(m)) if m.contains("protect") || m.contains("hidden") => {
                tripped = true;
                break;
            }
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
    assert!(tripped, "write into the hidden area was not blocked");

    // A blob exported after the trip starts read-only on the other side.
    let blob2 = ext.export_handoff().unwrap();
    let mut again = import(&path, &blob2).unwrap();
    assert!(again.vfs().create("/after.txt").is_err());
    ext.lock();
    again.lock();
    app.lock();

    // The hidden volume is intact.
    let mut hidden = unlock(&path, HIDDEN_PW);
    assert!(hidden.is_hidden());
    assert!(hidden.vfs().list("/").is_ok());
    std::fs::remove_file(&path).ok();
}

#[test]
fn two_sessions_interleaving_writes_stay_consistent() {
    vault_core::enable_handoff(true);
    for (i, fs) in [ContainerFs::Fat, ContainerFs::Exfat]
        .into_iter()
        .enumerate()
    {
        let path = make(&format!("two{i}"), "AES", fs);
        let mut app = unlock(&path, PW);
        let blob = app.export_handoff().unwrap();
        let mut ext = import(&path, &blob).unwrap();
        app.vfs().mkdir("/shared").unwrap();
        app.vfs().flush().unwrap();

        // The gate protocol the iOS shell follows: one writer at a time,
        // flush at the end of each operation, remount before the next
        // operation when the other side wrote in between.
        let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
        let mut last_writer = 0;
        for round in 0..24usize {
            let who = if round % 3 == 0 { 0 } else { 1 } ^ (round % 2);
            let s = if who == 0 { &mut app } else { &mut ext };
            if last_writer != who {
                s.remount().unwrap();
            }
            last_writer = who;
            let name = format!("/shared/f{round:02}-{who}.bin");
            let data = payload(round as u8, 3_000 + round * 9_000);
            write_file(s, &name, &data);
            if round % 5 == 4 {
                // Delete an earlier file to make the allocators reuse space.
                let (old, _) = expected.remove(0);
                s.vfs().unlink(&old).unwrap();
                s.vfs().flush().unwrap();
            }
            if round % 7 == 6 {
                let tmp_name = format!("/shared/.part-{round}");
                write_file(s, &tmp_name, &payload(99, 12_345));
                s.replace(&tmp_name, &name).unwrap();
                expected.push((name, payload(99, 12_345)));
                continue;
            }
            expected.push((name, data));
        }
        app.lock();
        ext.lock();

        let mut fresh = unlock(&path, PW);
        let mut want: Vec<String> = expected
            .iter()
            .map(|(n, _)| n.trim_start_matches("/shared/").to_string())
            .collect();
        want.sort();
        assert_eq!(names(&mut fresh, "/shared"), want);
        for (n, data) in &expected {
            assert_eq!(&read_file(&mut fresh, n), data, "{n}");
        }
        let space = fresh.space().unwrap();
        fresh.lock();
        fsck(&path, PW, fs);

        // The free count agrees with a recount by a brand-new session.
        let mut again = unlock(&path, PW);
        assert_eq!(again.space().unwrap(), space);
        again.lock();
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn replace_lands_the_temp_file_over_the_original() {
    vault_core::enable_handoff(true);
    for (i, fs) in [ContainerFs::Fat, ContainerFs::Exfat]
        .into_iter()
        .enumerate()
    {
        let path = make(&format!("replace{i}"), "AES", fs);
        let mut s = unlock(&path, PW);
        write_file(&mut s, "/doc.txt", b"version one, longer than the second");
        write_file(&mut s, "/.doc.part", b"version two");
        s.replace("/.doc.part", "/doc.txt").unwrap();
        assert_eq!(read_file(&mut s, "/doc.txt"), b"version two");
        assert!(s.vfs().stat("/.doc.part").is_err());
        // Replacing onto a name that doesn't exist is a plain rename.
        write_file(&mut s, "/.new.part", b"new file");
        s.replace("/.new.part", "/new.txt").unwrap();
        assert_eq!(read_file(&mut s, "/new.txt"), b"new file");
        // Directories are refused either way.
        s.vfs().mkdir("/dir").unwrap();
        write_file(&mut s, "/.x.part", b"x");
        assert!(s.replace("/.x.part", "/dir").is_err());
        assert!(s.replace("/dir", "/doc.txt").is_err());
        s.lock();
        fsck(&path, PW, fs);
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn replace_onto_the_same_entry_keeps_the_file() {
    vault_core::enable_handoff(true);
    for (i, fs) in [ContainerFs::Fat, ContainerFs::Exfat]
        .into_iter()
        .enumerate()
    {
        let path = make(&format!("same{i}"), "AES", fs);
        let mut s = unlock(&path, PW);
        write_file(&mut s, "/Doc.txt", b"keep me");
        s.replace("/Doc.txt", "/Doc.txt").unwrap();
        assert_eq!(read_file(&mut s, "/Doc.txt"), b"keep me");
        s.replace("/Doc.txt", "/doc.TXT").unwrap();
        assert_eq!(names(&mut s, "/"), vec!["doc.TXT"]);
        assert_eq!(read_file(&mut s, "/doc.TXT"), b"keep me");
        s.vfs().mkdir("/photos").unwrap();
        write_file(&mut s, "/photos/a.jpg", b"jpeg");
        s.replace("/photos", "/Photos").unwrap();
        assert_eq!(names(&mut s, "/"), vec!["Photos", "doc.TXT"]);
        assert_eq!(read_file(&mut s, "/Photos/a.jpg"), b"jpeg");
        s.lock();
        std::fs::remove_file(&path).ok();
    }
}

/// Without the gate's remount, exFAT's cached bitmap would hand both
/// sessions the same clusters. The allocator re-checks the disk before
/// claiming a cluster, so even a missed remount can't cross-link files.
#[test]
fn exfat_stale_bitmap_never_double_allocates() {
    vault_core::enable_handoff(true);
    let path = make("stale-exfat", "AES", ContainerFs::Exfat);
    let mut a = unlock(&path, PW);
    // Load a's bitmap cache now.
    let _ = a.space().unwrap();
    let blob = a.export_handoff().unwrap();
    let mut b = import(&path, &blob).unwrap();
    let _ = b.space().unwrap();
    let mut expected = Vec::new();
    for i in 0..8u8 {
        let s = if i % 2 == 0 { &mut a } else { &mut b };
        let name = format!("/f{i}.bin");
        let data = payload(i, 150_000);
        s.vfs().create(&name).unwrap();
        s.vfs().write_at(&name, 0, &data).unwrap();
        s.vfs().flush().unwrap();
        expected.push((name, data));
    }
    a.lock();
    b.lock();
    let mut fresh = unlock(&path, PW);
    for (n, data) in &expected {
        if fresh.vfs().stat(n).is_ok() {
            assert_eq!(&read_file(&mut fresh, n), data, "{n} corrupted");
        }
    }
    fresh.lock();
    fsck(&path, PW, ContainerFs::Exfat);
    std::fs::remove_file(&path).ok();
}

/// FAT32 (fatfs picks it from 512 MiB): FSInfo must stay right with two
/// sessions, including after a writer was killed without flushing and a
/// remounting session had recounted free space.
#[test]
fn fat32_fsinfo_survives_kill_recount_and_remount() {
    vault_core::enable_handoff(true);
    const BIG: u64 = 600 << 20;
    let path = tmp("fat32");
    std::fs::File::create(&path).unwrap().set_len(BIG).unwrap();
    let mut p = params("AES", PW);
    p.size = BIG;
    vault_core::create_container(
        Box::new(FileDevice::open_rw(&path).unwrap()),
        &p,
        ContainerFs::Fat,
    )
    .unwrap();

    // A writer allocates and dies without flushing.
    let mut killed = unlock(&path, PW);
    killed.vfs().create("/orphan.bin").unwrap();
    killed
        .vfs()
        .write_at("/orphan.bin", 0, &payload(1, 400_000))
        .unwrap();
    std::mem::forget(killed);

    let mut app = unlock(&path, PW);
    let _ = app.space().unwrap();
    let blob = app.export_handoff().unwrap();
    let mut ext = import(&path, &blob).unwrap();
    write_file(&mut ext, "/from-ext.bin", &payload(2, 3_000_000));
    ext.lock();
    app.remount().unwrap();
    app.lock();
    // The killed writer leaves the volume marked dirty, as any crash does,
    // so fatfs stops trusting FSInfo and leaves it "unknown". What must not
    // happen is a wrong count, or damage to any file.
    if let Some((_, report)) = fsck_report(&path, PW, ContainerFs::Fat) {
        for bad in [
            "summary wrong",
            "share clusters",
            "Truncating",
            "chain",
            "Orphaned",
        ] {
            assert!(!report.contains(bad), "fsck: {bad}\n{report}");
        }
    }
    let mut fresh = unlock(&path, PW);
    assert_eq!(
        read_file(&mut fresh, "/from-ext.bin"),
        payload(2, 3_000_000)
    );
    fresh.lock();
    std::fs::remove_file(&path).ok();
}
