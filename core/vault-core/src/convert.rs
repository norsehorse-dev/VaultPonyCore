//! Copy one open volume's files into another (2.0.0, plan 6.2, "Convert to
//! VeraCrypt"). The shells open a TrueCrypt volume (read-only), create a new
//! VeraCrypt container, open it, and hand both sessions here. The source is
//! only ever read; nothing here deletes or changes it.
//!
//! Policy matches the shells' bulk import (plan 2.5): names FAT and exFAT
//! can't store are cleaned up the same way (each of `\ / : * ? " < > |` and
//! control characters becomes `_`, trailing dots and spaces go, 255 UTF-16
//! units at most), and a name already taken in the destination folder (FAT
//! and exFAT compare without case) gets " (1)", " (2)"... Links and special
//! files (ext4) have no content to copy and are skipped and listed.
//!
//! After the copy, every file is checked in the destination by size and the
//! destination tree is counted again, so a short write or a lost entry fails
//! the conversion instead of passing silently.

use crate::Session;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use vc_types::{VcError, VcResult};

/// What a copy would do, for the shell's confirmation and pre-flight checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyPlan {
    pub files: u64,
    pub folders: u64,
    /// Bytes of file content.
    pub bytes: u64,
    /// Space the content takes in the destination (whole clusters per file).
    pub needed_bytes: u64,
    /// Links and special files, which are not copied.
    pub skipped: Vec<String>,
    /// Files larger than the destination filesystem allows (FAT: 4 GiB - 1).
    pub too_big: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyProgress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyReport {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    /// Items stored under a different name than in the source.
    pub renamed: u64,
    pub skipped: u64,
}

/// One end of a copy. Each filesystem call goes through `with`, so a shell
/// that shares the session behind a lock takes it per call, not for the
/// whole copy: locking the vault from elsewhere (auto-lock, "Lock all")
/// still works and simply ends the copy.
pub trait CopyEnd {
    fn with<T>(&mut self, f: impl FnOnce(&mut Session) -> VcResult<T>) -> VcResult<T>;
}

impl CopyEnd for Session {
    fn with<T>(&mut self, f: impl FnOnce(&mut Session) -> VcResult<T>) -> VcResult<T> {
        f(self)
    }
}

impl<E: CopyEnd + ?Sized> CopyEnd for &mut E {
    fn with<T>(&mut self, f: impl FnOnce(&mut Session) -> VcResult<T>) -> VcResult<T> {
        (**self).with(f)
    }
}

/// A session behind the shells' lock, `None` once it was locked. A copy that
/// finds its session locked stops with [`VcError::Cancelled`].
impl CopyEnd for &Mutex<Option<Session>> {
    fn with<T>(&mut self, f: impl FnOnce(&mut Session) -> VcResult<T>) -> VcResult<T> {
        let mut guard = self
            .lock()
            .map_err(|_| VcError::Internal("session lock poisoned".into()))?;
        match guard.as_mut() {
            Some(s) => f(s),
            None => Err(VcError::Cancelled),
        }
    }
}

const CHUNK: usize = 1 << 20;
const MAX_NAME_UNITS: usize = 255;

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn is_illegal(c: char) -> bool {
    matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || (c as u32) < 0x20
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// `stem + suffix + ext` within 255 UTF-16 units, shortening the stem.
fn fit(stem: &str, suffix: &str, ext: &str) -> String {
    let fixed = utf16_len(suffix) + utf16_len(ext);
    let mut units = 0;
    let mut cut = 0;
    for (i, c) in stem.char_indices() {
        if units + c.len_utf16() + fixed > MAX_NAME_UNITS {
            break;
        }
        units += c.len_utf16();
        cut = i + c.len_utf8();
    }
    format!("{}{suffix}{ext}", &stem[..cut])
}

/// The bulk-import rule: storable on FAT and exFAT, never "." or "..".
pub fn sanitize_name(name: &str) -> String {
    let replaced: String = name
        .chars()
        .map(|c| if is_illegal(c) { '_' } else { c })
        .collect();
    let mut out = replaced.trim_end_matches(['.', ' ']).to_string();
    if utf16_len(&out) > MAX_NAME_UNITS {
        let (stem, ext) = split_ext(&out);
        let (stem, ext) = if utf16_len(ext) >= MAX_NAME_UNITS / 2 {
            (out.as_str(), "")
        } else {
            (stem, ext)
        };
        out = fit(stem, "", ext).trim_end_matches(['.', ' ']).to_string();
    }
    if out.is_empty() {
        "_".into()
    } else {
        out
    }
}

/// First "name (n).ext" (or "name (n)" for folders) not in `taken`.
fn keep_both(name: &str, is_dir: bool, taken: &HashSet<String>) -> String {
    if !taken.contains(&name.to_lowercase()) {
        return name.to_string();
    }
    let (stem, ext) = if is_dir { (name, "") } else { split_ext(name) };
    let (stem, ext) = if utf16_len(ext) > MAX_NAME_UNITS / 2 {
        (name, "")
    } else {
        (stem, ext)
    };
    for n in 1u64.. {
        let candidate = fit(stem, &format!(" ({n})"), ext);
        if !taken.contains(&candidate.to_lowercase()) {
            return candidate;
        }
    }
    unreachable!()
}

/// Regular file vs folder vs something with no content to copy. ext4 links
/// and special files list as size-0 non-folders that refuse reads.
fn is_special(src: &mut impl CopyEnd, path: &str, e: &vc_fs::DirEntry) -> VcResult<bool> {
    if e.is_dir || e.size != 0 {
        return Ok(false);
    }
    src.with(|s| Ok(s.vfs().read_at(path, 0, &mut [0u8; 1]).is_err()))
}

/// Walk the source and say what a copy into `dst` would take.
pub fn plan_copy(mut src: impl CopyEnd, mut dst: impl CopyEnd) -> VcResult<CopyPlan> {
    let (cluster, max_file) = dst.with(|d| {
        Ok((
            d.space().map(|s| s.cluster_bytes).unwrap_or(0),
            d.max_file_bytes(),
        ))
    })?;
    let mut plan = CopyPlan::default();
    let mut stack = vec![String::from("/")];
    while let Some(dir) = stack.pop() {
        for e in src.with(|s| s.vfs().list(&dir))? {
            let path = join(&dir, &e.name);
            if e.is_dir {
                plan.folders += 1;
                stack.push(path);
            } else if is_special(&mut src, &path, &e)? {
                plan.skipped.push(path);
            } else {
                plan.files += 1;
                plan.bytes += e.size;
                plan.needed_bytes += if cluster == 0 {
                    e.size
                } else {
                    e.size.div_ceil(cluster).max(1) * cluster
                };
                if max_file.is_some_and(|m| e.size > m) {
                    plan.too_big.push(path);
                }
            }
        }
    }
    plan.skipped.sort();
    plan.too_big.sort();
    Ok(plan)
}

/// Counts for one volume, before any destination exists: lets a shell pick
/// exFAT when a file is over FAT's limit and suggest a container size.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TreeSummary {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    pub largest_file: u64,
}

/// Walk `src` and count it (links and special files are left out).
pub fn summarize_tree(mut src: impl CopyEnd) -> VcResult<TreeSummary> {
    let mut t = TreeSummary::default();
    let mut stack = vec![String::from("/")];
    while let Some(dir) = stack.pop() {
        for e in src.with(|s| s.vfs().list(&dir))? {
            let path = join(&dir, &e.name);
            if e.is_dir {
                t.folders += 1;
                stack.push(path);
            } else if !is_special(&mut src, &path, &e)? {
                t.files += 1;
                t.bytes += e.size;
                t.largest_file = t.largest_file.max(e.size);
            }
        }
    }
    Ok(t)
}

struct Copier<'a, S: CopyEnd, D: CopyEnd> {
    src: S,
    dst: D,
    cancel: Option<&'a AtomicBool>,
    progress: &'a mut dyn FnMut(&CopyProgress),
    state: CopyProgress,
    report: CopyReport,
    /// (destination path, source size) for every copied file.
    copied: Vec<(String, u64)>,
    buf: Vec<u8>,
}

impl<S: CopyEnd, D: CopyEnd> Copier<'_, S, D> {
    fn check_cancel(&self) -> VcResult<()> {
        if self.cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            Err(VcError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn copy_dir(&mut self, src_dir: &str, dst_dir: &str) -> VcResult<()> {
        let mut taken: HashSet<String> = self
            .dst
            .with(|d| d.vfs().list(dst_dir))?
            .into_iter()
            .map(|e| e.name.to_lowercase())
            .collect();
        let mut entries = self.src.with(|s| s.vfs().list(src_dir))?;
        // Folders first, then files, each by name: a stable order makes
        // renames ("a (1)") the same on every run.
        entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
        for e in entries {
            self.check_cancel()?;
            let src_path = join(src_dir, &e.name);
            if is_special(&mut self.src, &src_path, &e)? {
                self.report.skipped += 1;
                continue;
            }
            let clean = sanitize_name(&e.name);
            let name = keep_both(&clean, e.is_dir, &taken);
            if name != e.name {
                self.report.renamed += 1;
            }
            taken.insert(name.to_lowercase());
            let dst_path = join(dst_dir, &name);
            if e.is_dir {
                self.dst.with(|d| d.vfs().mkdir(&dst_path))?;
                self.report.folders += 1;
                self.copy_dir(&src_path, &dst_path)?;
            } else {
                self.copy_file(&src_path, &dst_path, e.size)?;
            }
        }
        Ok(())
    }

    fn copy_file(&mut self, src_path: &str, dst_path: &str, size: u64) -> VcResult<()> {
        self.dst.with(|d| d.vfs().create(dst_path))?;
        let result = self.copy_bytes(src_path, dst_path, size);
        if result.is_err() {
            // Never leave a short file under a real name.
            let _ = self.dst.with(|d| {
                let _ = d.vfs().unlink(dst_path);
                d.vfs().flush()
            });
            return result;
        }
        self.copied.push((dst_path.to_string(), size));
        self.report.files += 1;
        self.report.bytes += size;
        self.state.files_done += 1;
        (self.progress)(&self.state);
        Ok(())
    }

    fn copy_bytes(&mut self, src_path: &str, dst_path: &str, size: u64) -> VcResult<()> {
        let mut off = 0u64;
        while off < size {
            self.check_cancel()?;
            let want = CHUNK.min((size - off) as usize);
            let buf = &mut self.buf[..want];
            let n = self.src.with(|s| s.vfs().read_at(src_path, off, buf))?;
            if n == 0 {
                return Err(VcError::Filesystem(format!("{src_path}: ended early")));
            }
            let data = &self.buf[..n];
            self.dst.with(|d| {
                let mut w = 0;
                while w < data.len() {
                    let m = d.vfs().write_at(dst_path, off + w as u64, &data[w..])?;
                    if m == 0 {
                        return Err(VcError::Filesystem(format!("{dst_path}: write stalled")));
                    }
                    w += m;
                }
                Ok(())
            })?;
            off += n as u64;
            self.state.bytes_done += n as u64;
            (self.progress)(&self.state);
        }
        Ok(())
    }

    fn verify(&mut self) -> VcResult<()> {
        for (path, size) in &self.copied {
            let st = self.dst.with(|d| d.vfs().stat(path))?;
            if st.is_dir || st.size != *size {
                return Err(VcError::Filesystem(format!(
                    "{path}: copied {} bytes, expected {size}",
                    st.size
                )));
            }
        }
        let (mut files, mut folders) = (0u64, 0u64);
        let mut stack = vec![String::from("/")];
        while let Some(dir) = stack.pop() {
            for e in self.dst.with(|d| d.vfs().list(&dir))? {
                if e.is_dir {
                    folders += 1;
                    stack.push(join(&dir, &e.name));
                } else {
                    files += 1;
                }
            }
        }
        if files < self.report.files || folders < self.report.folders {
            return Err(VcError::Filesystem(format!(
                "the new volume holds {files} files and {folders} folders, expected {} and {}",
                self.report.files, self.report.folders
            )));
        }
        Ok(())
    }
}

/// Copy everything in `src` into the root of `dst`, then verify it. `dst`
/// should be a freshly created, empty volume; anything already there is
/// kept (names are chosen around it). Refuses up front when a file is too
/// large for `dst` or `dst` lacks the space (see [`plan_copy`]). On cancel
/// or error the partly written file is removed; files and folders already
/// copied stay, and the caller decides whether to delete the new container.
pub fn copy_tree<S: CopyEnd, D: CopyEnd>(
    mut src: S,
    mut dst: D,
    cancel: Option<&AtomicBool>,
    progress: &mut dyn FnMut(&CopyProgress),
) -> VcResult<CopyReport> {
    if !dst.with(|d| Ok(d.vfs().writable()))? {
        return Err(VcError::Filesystem(
            "the destination volume is read-only".into(),
        ));
    }
    let plan = plan_copy(&mut src, &mut dst)?;
    if let Some(p) = plan.too_big.first() {
        return Err(VcError::Filesystem(format!(
            "{p} is larger than the new volume's filesystem allows"
        )));
    }
    if let Ok(space) = dst.with(|d| d.space()) {
        if plan.needed_bytes > space.free_bytes {
            return Err(VcError::Filesystem(format!(
                "the new volume needs {} bytes free, it has {}",
                plan.needed_bytes, space.free_bytes
            )));
        }
    }
    let mut c = Copier {
        src,
        dst,
        cancel,
        progress,
        state: CopyProgress {
            files_total: plan.files,
            bytes_total: plan.bytes,
            ..Default::default()
        },
        report: CopyReport::default(),
        copied: Vec::with_capacity(plan.files as usize),
        buf: vec![0u8; CHUNK],
    };
    (c.progress)(&c.state);
    let result = c.copy_dir("/", "/");
    c.dst.with(|d| d.vfs().flush())?;
    result?;
    c.verify()?;
    Ok(c.report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_bulk_import_rule() {
        assert_eq!(sanitize_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(sanitize_name("trailing. . "), "trailing");
        assert_eq!(sanitize_name(".."), "_");
        assert_eq!(sanitize_name("tab\there"), "tab_here");
        let long = format!("{}.jpeg", "x".repeat(300));
        let s = sanitize_name(&long);
        assert_eq!(utf16_len(&s), 255);
        assert!(s.ends_with(".jpeg"));
    }

    #[test]
    fn taken_names_get_a_number_without_case() {
        let taken: HashSet<String> = ["photo.jpg", "photo (1).jpg", "docs"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(keep_both("Photo.JPG", false, &taken), "Photo (2).JPG");
        assert_eq!(keep_both("Docs", true, &taken), "Docs (1)");
        assert_eq!(keep_both("new.txt", false, &taken), "new.txt");
    }
}
