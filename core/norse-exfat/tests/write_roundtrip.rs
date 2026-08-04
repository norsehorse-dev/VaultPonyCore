//! Write with norse-exfat, read it back with norse-exfat, over a fresh
//! mkfs.exfat image. This is the fast inner loop; the reference-driver
//! differential fuzz (in vc-fs) is the P5 gate proper.

use norse_exfat::{ExfatFs, ReadAt, WriteAt};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::Command;

struct FileDev(std::fs::File);
impl ReadAt for FileDev {
    fn read_at(&mut self, o: u64, b: &mut [u8]) -> std::io::Result<()> {
        self.0.seek(SeekFrom::Start(o))?;
        self.0.read_exact(b)
    }
    fn len(&mut self) -> std::io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
}
impl WriteAt for FileDev {
    fn write_at(&mut self, o: u64, b: &[u8]) -> std::io::Result<()> {
        self.0.seek(SeekFrom::Start(o))?;
        self.0.write_all(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Write::flush(&mut self.0)
    }
}

fn fresh_image(bytes: u64) -> Option<std::path::PathBuf> {
    if Command::new("mkfs.exfat").arg("--help").output().is_err() {
        return None;
    }
    let p = std::env::temp_dir().join(format!("vp-exw-{}.img", std::process::id()));
    std::fs::write(&p, vec![0u8; bytes as usize]).unwrap();
    let ok = Command::new("mkfs.exfat")
        .args(["-c", "32k", p.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success();
    if !ok {
        return None;
    }
    Some(p)
}

fn open(p: &std::path::Path) -> ExfatFs<FileDev> {
    ExfatFs::open(FileDev(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .unwrap(),
    ))
    .unwrap()
}

#[test]
fn create_write_grow_delete_roundtrip() {
    let Some(img) = fresh_image(32 << 20) else {
        eprintln!("SKIP: mkfs.exfat not installed");
        return;
    };

    // Create files and directories, write content, then read it all back.
    let big: Vec<u8> = (0..500_000u32).map(|i| (i * 7) as u8).collect();
    {
        let mut fs = open(&img);
        fs.make_dir("/docs").unwrap();
        fs.create_file("/docs/a.txt").unwrap();
        fs.write_file("/docs/a.txt", 0, b"hello exfat write")
            .unwrap();
        fs.create_file("/big.bin").unwrap();
        fs.write_file("/big.bin", 0, &big).unwrap();
        // Enough small files to force the root directory to grow past one
        // cluster's worth of entry sets.
        for i in 0..300 {
            let p = format!("/f{i:04}.dat");
            fs.create_file(&p).unwrap();
            fs.write_file(&p, 0, format!("file {i}").as_bytes())
                .unwrap();
        }
        // Delete half of them.
        for i in (0..300).step_by(2) {
            fs.remove(&format!("/f{i:04}.dat")).unwrap();
        }
    }

    // Reopen and verify with the reader.
    {
        let mut fs = open(&img);
        let (fc, nfc, dl) = fs.root_dir();
        let names: Vec<String> = fs
            .list_dir(fc, nfc, dl)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"docs".to_string()));
        assert!(names.contains(&"big.bin".to_string()));
        assert!(names.contains(&"f0001.dat".to_string())); // odd kept
        assert!(!names.contains(&"f0000.dat".to_string())); // even deleted

        let a = fs.lookup("/docs/a.txt").unwrap().unwrap();
        let mut buf = vec![0u8; a.size as usize];
        fs.read_file(&a, 0, &mut buf).unwrap();
        assert_eq!(buf, b"hello exfat write");

        let b = fs.lookup("/big.bin").unwrap().unwrap();
        assert_eq!(b.size, big.len() as u64);
        let mut buf = vec![0u8; big.len()];
        fs.read_file(&b, 0, &mut buf).unwrap();
        assert_eq!(buf, big);
    }

    let _ = std::fs::remove_file(&img);
}
