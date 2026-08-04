//! vaultpony — headless CLI (planning doc §10).
//!
//! Doubles as the P0 test harness and the support tool ("run this, paste the
//! output"). Subcommand surface matches the doc: unlock/list/extract/add,
//! header backup/restore, volume info.
//!
//! License note: apps are GPL-3.0 under the proposed split (doc §14, open
//! decision §16); flip here and in Cargo.toml if that decision changes.

use clap::{Parser, Subcommand};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "vaultpony",
    version,
    about = "VeraCrypt container tool (userspace, no admin)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new VeraCrypt-compatible container (doc §10). Desktop
    /// VeraCrypt can open what this produces.
    Create {
        container: PathBuf,
        /// Total size in bytes.
        #[arg(long)]
        size: u64,
        /// Encryption scheme name, e.g. "AES", "AES(Twofish)".
        #[arg(long, default_value = "AES")]
        encryption: String,
        /// PRF/hash name, e.g. "SHA-512", "Whirlpool".
        #[arg(long, default_value = "SHA-512")]
        hash: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        /// Keyfile path (repeatable).
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        /// Filesystem to format inside: "FAT" or "exFAT".
        #[arg(long, default_value = "FAT")]
        filesystem: String,
    },
    /// Create a container with a hidden volume inside it (doc §9). The outer
    /// password (VAULTPONY_PASSWORD or a prompt) is the decoy; the hidden
    /// password (VAULTPONY_HIDDEN_PASSWORD or a prompt) opens the concealed
    /// volume. Desktop VeraCrypt can mount both.
    CreateHidden {
        container: PathBuf,
        /// Total size in bytes.
        #[arg(long)]
        size: u64,
        /// Hidden volume data-area size in bytes (carved from the tail).
        #[arg(long = "hidden-size")]
        hidden_size: u64,
        /// Encryption scheme name, e.g. "AES", "AES(Twofish)".
        #[arg(long, default_value = "AES")]
        encryption: String,
        /// PRF/hash name, e.g. "SHA-512", "Whirlpool".
        #[arg(long, default_value = "SHA-512")]
        hash: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        /// Filesystem to format inside: "FAT" or "exFAT".
        #[arg(long, default_value = "FAT")]
        filesystem: String,
    },
    /// Show container/header info without extracting anything. Output is
    /// support-safe: parameters only, never names, paths, or key material.
    Info {
        container: PathBuf,
        /// Volume PIM (0 = default iteration schedule).
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
    /// List files inside an unlocked container (P0 gate: this working
    /// against the first fixture).
    List {
        container: PathBuf,
        #[arg(default_value = "/")]
        path: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
    /// Extract a file or tree to a local directory.
    Extract {
        container: PathBuf,
        /// Path inside the volume.
        from: String,
        /// Local destination directory.
        to: PathBuf,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
    /// Add a local file into the container (FAT; exFAT write lands in P5).
    Add {
        container: PathBuf,
        file: PathBuf,
        /// Destination directory inside the volume.
        #[arg(default_value = "/")]
        to: String,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        /// Protect a hidden volume while writing to this (outer) volume.
        /// Prompts for the hidden password too (or VAULTPONY_HIDDEN_PASSWORD);
        /// writes that would hit the hidden volume are refused (doc §9).
        #[arg(long)]
        protect_hidden: bool,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
    /// Back up the volume's header group (128 KiB, ciphertext) to a file.
    /// NOTE: a header backup lets an old password unlock the volume even
    /// after a password change — store it as carefully as the container.
    HeaderBackup { container: PathBuf, out: PathBuf },
    /// Restore the primary volume header (doc §6: the single highest-value
    /// support tool the format gives us). Verifies the replacement header
    /// unlocks with your password before writing anything.
    HeaderRestore {
        container: PathBuf,
        /// Restore from an external backup file instead of the embedded one.
        #[arg(long)]
        from_file: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        pim: u32,
    },
}

/// Passphrase entry: a no-echo prompt on a terminal, or (for scripting and
/// the test harness only) the VAULTPONY_PASSWORD environment variable.
/// Never an argument — secrets must not land in shell history or process
/// lists (doc §11).
fn read_passphrase() -> std::io::Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("VAULTPONY_PASSWORD") {
        return Ok(Zeroizing::new(p));
    }
    if !std::io::stdin().is_terminal() {
        return Err(std::io::Error::other(
            "stdin is not a terminal; set VAULTPONY_PASSWORD for scripted use",
        ));
    }
    Ok(Zeroizing::new(rpassword::prompt_password("Password: ")?))
}

fn read_keyfiles(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, ExitCode> {
    paths
        .iter()
        .map(|p| {
            std::fs::read(p).map_err(|e| {
                eprintln!("error reading keyfile {}: {e}", p.display());
                ExitCode::FAILURE
            })
        })
        .collect()
}

/// Read the passphrase and fold in any keyfiles → the effective secret fed
/// to the core (doc §4). Wiped on drop.
fn effective_secret(keyfiles: &[PathBuf]) -> Result<Zeroizing<Vec<u8>>, ExitCode> {
    let passphrase = read_passphrase().map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    })?;
    let kf = read_keyfiles(keyfiles)?;
    Ok(vc_crypto::apply_keyfiles(passphrase.as_bytes(), &kf))
}

fn cmd_info(container: PathBuf, pim: u32, keyfiles: Vec<PathBuf>) -> ExitCode {
    let secret = match effective_secret(&keyfiles) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut last = String::new();
    let result = vault_core::probe(&container, &secret, pim, &mut |i, n, prf| {
        if std::io::stderr().is_terminal() {
            last = format!("trying {prf} ({}/{n})...", i + 1);
            eprint!("\r{last}");
            let _ = std::io::stderr().flush();
        }
    });
    if !last.is_empty() {
        eprintln!();
    }
    match result {
        Ok(info) => {
            println!("scheme:               {}", info.scheme);
            println!("prf:                  {}", info.prf);
            println!("header:               {:?}", info.source);
            println!("header version:       {}", info.header_version);
            println!("min program version:  {:#06x}", info.min_program_version);
            println!("volume size:          {} bytes", info.geometry.volume_size);
            println!("sector size:          {}", info.geometry.sector_size);
            println!(
                "data area:            offset {}, {} bytes",
                info.geometry.encrypted_area_start, info.geometry.encrypted_area_size
            );
            println!("filesystem:           {:?}", info.filesystem);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn unlock(
    container: &std::path::Path,
    pim: u32,
    keyfiles: &[PathBuf],
) -> Result<vault_core::Session, ExitCode> {
    unlock_mode(container, pim, false, keyfiles)
}

fn unlock_mode(
    container: &std::path::Path,
    pim: u32,
    writable: bool,
    keyfiles: &[PathBuf],
) -> Result<vault_core::Session, ExitCode> {
    let secret = effective_secret(keyfiles)?;
    let mut last = String::new();
    let session =
        vault_core::Session::unlock_with(container, &secret, pim, writable, &mut |i, n, prf| {
            if std::io::stderr().is_terminal() {
                last = format!("trying {prf} ({}/{n})...", i + 1);
                eprint!("\r{last}");
                let _ = std::io::stderr().flush();
            }
        });
    if !last.is_empty() {
        eprintln!();
    }
    session.map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    })
}

fn cmd_list(container: PathBuf, path: String, pim: u32, keyfiles: Vec<PathBuf>) -> ExitCode {
    let mut session = match unlock(&container, pim, &keyfiles) {
        Ok(s) => s,
        Err(code) => return code,
    };
    match session.vfs().list(&path) {
        Ok(mut entries) => {
            entries.sort_by(|a, b| {
                (b.is_dir, a.name.to_lowercase()).cmp(&(a.is_dir, b.name.to_lowercase()))
            });
            for e in entries {
                if e.is_dir {
                    println!("{:>12}  {}/", "<dir>", e.name);
                } else {
                    println!("{:>12}  {}", e.size, e.name);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Recursively extract `from` (file or directory) into local directory `to`.
fn extract_tree(
    vfs: &mut dyn vc_fs::Vfs,
    from: &str,
    to: &std::path::Path,
) -> Result<usize, String> {
    let st = vfs.stat(from).map_err(|e| e.to_string())?;
    if !st.is_dir {
        let dest = to.join(&st.name);
        let mut out = std::fs::File::create(&dest).map_err(|e| e.to_string())?;
        let mut offset = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = vfs
                .read_at(from, offset, &mut buf)
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            offset += n as u64;
        }
        return Ok(1);
    }
    let sub = if st.name == "/" {
        to.to_path_buf()
    } else {
        to.join(&st.name)
    };
    std::fs::create_dir_all(&sub).map_err(|e| e.to_string())?;
    let mut count = 0;
    for entry in vfs.list(from).map_err(|e| e.to_string())? {
        let child = format!("{}/{}", from.trim_end_matches('/'), entry.name);
        count += extract_tree(vfs, &child, &sub)?;
    }
    Ok(count)
}

/// Outer-volume unlock with hidden protection (doc §9). Reads the outer
/// password, then the hidden password (VAULTPONY_HIDDEN_PASSWORD or a
/// no-echo prompt).
fn unlock_protected(
    container: &std::path::Path,
    pim: u32,
    keyfiles: &[PathBuf],
) -> Result<vault_core::Session, ExitCode> {
    // Keyfiles apply to the outer password (the one being written under).
    let outer = effective_secret(keyfiles)?;
    let hidden = match std::env::var("VAULTPONY_HIDDEN_PASSWORD") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => {
            if !std::io::stdin().is_terminal() {
                eprintln!("error: set VAULTPONY_HIDDEN_PASSWORD for scripted protected writes");
                return Err(ExitCode::FAILURE);
            }
            Zeroizing::new(
                rpassword::prompt_password("Hidden volume password: ").map_err(|e| {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                })?,
            )
        }
    };
    vault_core::Session::unlock_outer_protected(
        container,
        &outer,
        hidden.as_bytes(),
        pim,
        &mut |_, _, _| {},
    )
    .map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    })
}

fn cmd_add(
    container: PathBuf,
    file: PathBuf,
    to: String,
    pim: u32,
    protect_hidden: bool,
    keyfiles: Vec<PathBuf>,
) -> ExitCode {
    let data = match std::fs::read(&file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error reading input: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(name) = file.file_name().and_then(|n| n.to_str()) else {
        eprintln!("error: input file has no usable name");
        return ExitCode::FAILURE;
    };
    let mut session = if protect_hidden {
        match unlock_protected(&container, pim, &keyfiles) {
            Ok(s) => s,
            Err(code) => return code,
        }
    } else {
        match unlock_mode(&container, pim, true, &keyfiles) {
            Ok(s) => s,
            Err(code) => return code,
        }
    };
    let vfs = session.vfs();
    if !vfs.writable() {
        eprintln!("error: this filesystem is read-only for now");
        return ExitCode::FAILURE;
    }
    let dest = format!("{}/{}", to.trim_end_matches('/'), name);
    let result = vfs
        .create(&dest)
        .and_then(|_| vfs.write_at(&dest, 0, &data))
        .and_then(|_| vfs.truncate(&dest, data.len() as u64))
        .and_then(|_| vfs.flush());
    match result {
        Ok(()) => {
            eprintln!("added {name} ({} bytes)", data.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_header_backup(container: PathBuf, out: PathBuf) -> ExitCode {
    let result = vc_io::FileDevice::open_read(&container)
        .and_then(|mut dev| vc_format::repair::export_headers(&mut dev))
        .and_then(|bytes| std::fs::write(&out, bytes).map_err(Into::into));
    match result {
        Ok(()) => {
            eprintln!("header group backed up (128 KiB)");
            eprintln!("note: this backup accepts the CURRENT password forever, even after a password change — guard it like the container itself");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_header_restore(container: PathBuf, from_file: Option<PathBuf>, pim: u32) -> ExitCode {
    let passphrase = match read_passphrase() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let secret = vc_format::UnlockSecret {
        passphrase: passphrase.as_bytes(),
        pim,
    };
    let result = vc_io::FileDevice::open_rw(&container).and_then(|mut dev| match &from_file {
        Some(path) => {
            let backup = std::fs::read(path)?;
            vc_format::repair::restore_from_file(&mut dev, &backup, &secret)
        }
        None => vc_format::repair::restore_primary_from_embedded(&mut dev, &secret),
    });
    match result {
        Ok(found) => {
            eprintln!(
                "primary header restored and verified ({} / {})",
                found.scheme.name, found.prf.name
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e} (nothing was written)");
            ExitCode::FAILURE
        }
    }
}

fn cmd_extract(
    container: PathBuf,
    from: String,
    to: PathBuf,
    pim: u32,
    keyfiles: Vec<PathBuf>,
) -> ExitCode {
    let mut session = match unlock(&container, pim, &keyfiles) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if let Err(e) = std::fs::create_dir_all(&to) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    match extract_tree(session.vfs(), &from, &to) {
        Ok(n) => {
            eprintln!("extracted {n} file(s)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    env_logger::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Create {
            container,
            size,
            encryption,
            hash,
            pim,
            keyfiles,
            filesystem,
        } => cmd_create(container, size, encryption, hash, pim, keyfiles, filesystem),
        Command::CreateHidden {
            container,
            size,
            hidden_size,
            encryption,
            hash,
            pim,
            filesystem,
        } => cmd_create_hidden(container, size, hidden_size, encryption, hash, pim, filesystem),
        Command::Info {
            container,
            pim,
            keyfiles,
        } => cmd_info(container, pim, keyfiles),
        Command::List {
            container,
            path,
            pim,
            keyfiles,
        } => cmd_list(container, path, pim, keyfiles),
        Command::Extract {
            container,
            from,
            to,
            pim,
            keyfiles,
        } => cmd_extract(container, from, to, pim, keyfiles),
        Command::Add {
            container,
            file,
            to,
            pim,
            protect_hidden,
            keyfiles,
        } => cmd_add(container, file, to, pim, protect_hidden, keyfiles),
        Command::HeaderBackup { container, out } => cmd_header_backup(container, out),
        Command::HeaderRestore {
            container,
            from_file,
            pim,
        } => cmd_header_restore(container, from_file, pim),
    }
}

/// Map a filesystem name to the core enum.
fn parse_fs(name: &str) -> Result<vault_core::ContainerFs, ExitCode> {
    match name {
        "FAT" | "fat" => Ok(vault_core::ContainerFs::Fat),
        "exFAT" | "exfat" | "EXFAT" => Ok(vault_core::ContainerFs::Exfat),
        _ => {
            eprintln!("error: unknown filesystem {name:?} (use FAT or exFAT)");
            Err(ExitCode::FAILURE)
        }
    }
}

fn cmd_create_hidden(
    container: PathBuf,
    size: u64,
    hidden_size: u64,
    encryption: String,
    hash: String,
    pim: u32,
    filesystem: String,
) -> ExitCode {
    let fs = match parse_fs(&filesystem) {
        Ok(f) => f,
        Err(c) => return c,
    };
    let Some(scheme) = vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == encryption)
    else {
        eprintln!("error: unknown encryption scheme {encryption:?}");
        return ExitCode::FAILURE;
    };
    let Some(prf) = vc_types::registry::PRFS.iter().find(|p| p.name == hash) else {
        eprintln!("error: unknown hash {hash:?}");
        return ExitCode::FAILURE;
    };
    // Outer (decoy) password, then hidden password.
    let outer_pw = match read_passphrase() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let hidden_pw = match read_hidden_passphrase() {
        Ok(p) => p,
        Err(code) => return code,
    };
    if outer_pw.as_bytes() == hidden_pw.as_bytes() {
        eprintln!("error: the outer and hidden passwords must differ");
        return ExitCode::FAILURE;
    }
    // Create the backing file sparse (set_len, not a zeroed buffer) so large
    // containers don't allocate their full size in RAM or on disk up front.
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&container)
        .and_then(|f| f.set_len(size))
    {
        eprintln!("error creating file: {e}");
        return ExitCode::FAILURE;
    }
    let make = || -> vc_types::VcResult<Box<dyn vc_io::BlockDevice>> {
        Ok(Box::new(vc_io::FileDevice::open_rw(&container)?))
    };
    let outer = vc_format::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: outer_pw.as_bytes(),
        keyfiles: &[],
        size,
        sector_size: 512,
    };
    let hidden = vc_format::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: hidden_pw.as_bytes(),
        keyfiles: &[],
        size,
        sector_size: 512,
    };
    match vault_core::create_container_with_hidden(make, &outer, &hidden, hidden_size, fs) {
        Ok(()) => {
            eprintln!(
                "created {encryption} / {hash} / {filesystem} container with a {hidden_size}-byte hidden volume"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read the hidden-volume password: VAULTPONY_HIDDEN_PASSWORD, or a no-echo
/// prompt on a terminal.
fn read_hidden_passphrase() -> Result<Zeroizing<String>, ExitCode> {
    match std::env::var("VAULTPONY_HIDDEN_PASSWORD") {
        Ok(p) => Ok(Zeroizing::new(p)),
        Err(_) => {
            if !std::io::stdin().is_terminal() {
                eprintln!("error: set VAULTPONY_HIDDEN_PASSWORD for scripted use");
                return Err(ExitCode::FAILURE);
            }
            let p = rpassword::prompt_password("Hidden volume password: ").map_err(|e| {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            })?;
            Ok(Zeroizing::new(p))
        }
    }
}

fn cmd_create(
    container: PathBuf,
    size: u64,
    encryption: String,
    hash: String,
    pim: u32,
    keyfiles: Vec<PathBuf>,
    filesystem: String,
) -> ExitCode {
    let fs = match parse_fs(&filesystem) {
        Ok(f) => f,
        Err(c) => return c,
    };
    let Some(scheme) = vc_types::registry::ENCRYPTION_SCHEMES
        .iter()
        .find(|s| s.name == encryption)
    else {
        eprintln!("error: unknown encryption scheme {encryption:?}");
        return ExitCode::FAILURE;
    };
    let Some(prf) = vc_types::registry::PRFS.iter().find(|p| p.name == hash) else {
        eprintln!("error: unknown hash {hash:?}");
        return ExitCode::FAILURE;
    };
    let passphrase = match read_passphrase() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let kf = match read_keyfiles(&keyfiles) {
        Ok(k) => k,
        Err(code) => return code,
    };
    // Create the backing file sparse (set_len, not a zeroed buffer) so large
    // containers don't allocate their full size in RAM or on disk up front.
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&container)
        .and_then(|f| f.set_len(size))
    {
        eprintln!("error creating file: {e}");
        return ExitCode::FAILURE;
    }
    let dev = match vc_io::FileDevice::open_rw(&container) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let params = vc_format::CreateParams {
        scheme,
        prf,
        pim,
        passphrase: passphrase.as_bytes(),
        keyfiles: &kf,
        size,
        sector_size: 512,
    };
    match vault_core::create_container(Box::new(dev), &params, fs) {
        Ok(()) => {
            eprintln!("created {encryption} / {hash} / {filesystem} container with an empty filesystem");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
