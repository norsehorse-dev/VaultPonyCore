//! Differential parity vs the reference driver (doc §7): every file in
//! every reference image reads back byte-identical to what the FUSE exFAT
//! driver recorded in the manifest, and nothing extra or missing appears.
//!
//! Images come from tools/gen-fixtures/create_exfat_images.py; location is
//! $EXFAT_IMAGES (skips politely when absent).

use norse_exfat::{Entry, ExfatFs, ReadAt};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

struct FileReadAt(File);

impl ReadAt for FileReadAt {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.0.seek(SeekFrom::Start(offset))?;
        self.0.read_exact(buf)
    }
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
}

fn images_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("EXFAT_IMAGES").map(PathBuf::from)?;
    dir.join("manifest.json").exists().then_some(dir)
}

fn collect_files(
    fs: &mut ExfatFs<FileReadAt>,
    dir: (u32, bool, u64),
    prefix: &str,
    out: &mut Vec<(String, Entry)>,
) {
    for e in fs.list_dir(dir.0, dir.1, dir.2).unwrap() {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        if e.is_dir {
            collect_files(fs, (e.first_cluster, e.no_fat_chain, e.size), &path, out);
        } else {
            out.push((path, e));
        }
    }
}

#[test]
fn every_reference_file_reads_back_byte_identical() {
    let Some(dir) = images_dir() else {
        eprintln!("SKIP: reference images not present (set EXFAT_IMAGES)");
        return;
    };
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();

    for (name, img) in manifest["images"].as_object().unwrap() {
        let path = dir.join(img["file"].as_str().unwrap());
        let mut fs = ExfatFs::open(FileReadAt(File::open(&path).unwrap()))
            .unwrap_or_else(|e| panic!("{name}: open: {e}"));

        let mut ours = Vec::new();
        let root = fs.root_dir();
        collect_files(&mut fs, root, "", &mut ours);

        let want = img["tree"].as_object().unwrap();
        assert_eq!(
            ours.len(),
            want.len(),
            "{name}: file count mismatch (ours: {:?})",
            ours.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );

        for (path, entry) in &ours {
            let want_hex = want
                .get(path)
                .unwrap_or_else(|| panic!("{name}: unexpected file {path}"))
                .as_str()
                .unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 256 * 1024];
            let mut offset = 0u64;
            loop {
                let n = fs.read_file(entry, offset, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                offset += n as u64;
            }
            assert_eq!(offset, entry.size, "{name}/{path}: length");
            let got: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(got, want_hex, "{name}/{path}: content mismatch");
        }
        eprintln!("{name}: {} files parity-verified", ours.len());
    }
}

#[test]
fn lookup_is_case_insensitive_via_upcase_table() {
    let Some(dir) = images_dir() else {
        eprintln!("SKIP: reference images not present");
        return;
    };
    let path = dir.join("exfat-default-16m.img");
    let mut fs = ExfatFs::open(FileReadAt(File::open(path).unwrap())).unwrap();
    let a = fs.lookup("README.TXT").unwrap().unwrap();
    let b = fs.lookup("readme.txt").unwrap().unwrap();
    assert_eq!(a.first_cluster, b.first_cluster);
    assert!(fs.lookup("no/such/file").is_err());
}
