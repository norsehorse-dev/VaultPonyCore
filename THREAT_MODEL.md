# VaultPony Threat Model

Status: living document, present from P0 (planning doc §11). Every claim
here is either enforced by code and CI, or explicitly marked out of scope.
If a feature can't be shipped without weakening this document, the document
wins until the change is argued here first, in the same PR.

## What VaultPony is

A local-only tool for opening and editing VeraCrypt file containers on
Android, iOS, and desktop. It has no server, no accounts, no telemetry, and
no network code at all. The security-relevant surface is: the container
parser, the crypto path, memory handling of secrets, and what the OS can
observe about usage.

## Assets

1. **Container contents**, the files inside a mounted volume. The primary
   asset.
2. **Secrets in flight**, passphrases, PIM values, derived header keys,
   master keys, and decrypted plaintext buffers.
3. **Usage metadata**, filenames, container names/paths, the fact that a
   given file *is* a VeraCrypt container, and remembered unlock parameters.
   Lower value than 1 and 2 but explicitly in scope: this app's audience is
   deniability-adjacent, and metadata is what apps leak by accident.

## In scope

### Confidentiality of container contents at rest

- The container on disk is protected by VeraCrypt's format. Our job is to
  not undermine it: no plaintext ever written outside an explicit,
  user-initiated export.
- Where a temporary plaintext file is unavoidable (iOS QuickLook), it lives
  in the app sandbox `tmp/` only, with the `.complete` (NSFileProtection)
  class, and is deleted on viewer close and on lock. Android viewers use
  proxy file descriptors precisely so extraction is not needed for viewing.
- Caches (read-ahead, thumbnails if ever added) hold plaintext in memory
  only. Anything that would persist derived-from-plaintext data to disk is a
  design change that must be argued in this file first.

### Secret hygiene in memory

- Every key container in the Rust core is `zeroize`-on-drop; passphrases
  and keys have single owners and minimal copies by construction.
- Locking a volume zeroizes keys through every layer via one code path
  (`Session::lock`); auto-lock (timeout, screen-off policy) and explicit
  lock use that same path.
- Secrets crossing the FFI boundary use callback-scoped buffers wiped after
  use; the generated Kotlin/Swift glue is audited for lingering copies as
  part of the FFI review checklist (vault-ffi doc comment).
- No secret, filename, container path, or volume metadata is ever written
  to logs, error strings, analytics (there are none), or crash output.
  Error variants in `vc-types` are designed to be user-explainable without
  embedding user data.

### No network attack surface

- The Android manifest declares no INTERNET permission; iOS ships no
  networking code; the Rust core links no network crates (`cargo-deny`
  enforces the dependency policy). "Zero network" is a headline feature and
  a testable property, not a promise.
- Consequence accepted: no update checks, no online anything. Updates come
  from the store/F-Droid/GitHub channel the user chose.

### Parser robustness

- A container is attacker-controlled input: a malicious container must not
  be able to escalate beyond a clean, safe error. Header parsing and
  filesystem metadata parsing (especially `norse-exfat` directory sets) are
  fuzz targets from day one (`cargo-fuzz` in CI, doc §13), and the core is
  memory-safe Rust with `unsafe` treated as a code-review event.

### Hidden-volume read (P8): deniability properties

Hidden-volume read has shipped. What the implementation guarantees, and how
it is enforced (verified in `vault-core/tests/hidden_gate.rs`):

- **The password alone selects the volume.** Unlock probes primary, hidden,
  and both embedded backups; whichever slot the password validates is what
  opens. There is no "open hidden" flag to fat-finger or to leak in a
  screenshot, the outer password opens the outer volume, the hidden
  password opens the hidden one, and neither can reach the other's data.
- **Constant work regardless of hidden presence.** A wrong password walks
  the full position list before failing, and the returned error is the same
  `NotFoundOrWrongPassword` a normal container with no hidden volume gives.
  A container with a hidden volume and one without are indistinguishable to
  anyone who does not hold the hidden password, by timing or by error.
- **No position leaks into support output.** `vaultpony info` (built to be
  pasted into a support thread, doc §10) collapses the header source to
  `Primary`/`Backup`; the word "Hidden" never appears. The core carries the
  precise `HeaderPosition` internally but no logging, error string, or
  support surface emits it (enforced: the search path in `vc-format` links
  no logging facade at all, grep-verified in review).
- **No trace from probing.** Probing the hidden slot writes nothing, logs
  nothing, and leaves no UI history; the parameter cache (when it lands)
  keys on the outer salt and records no evidence a hidden slot was tried.

Standing constraint for the shells: a hidden volume, once open, browses
exactly like any other, the app must not label it "hidden" in any
persistent or system-visible surface (recents, notifications, the mount
list a screenshot could capture). The one place volume type is
observable, the geometry of what you unlocked, is visible only to the
process that already holds the hidden password.

### Hidden-volume write protection (P9)

Writing to an outer volume can destroy the hidden volume that occupies its
free space, desktop VeraCrypt warns about exactly this. `unlock_outer_
protected` takes both passwords: the outer password mounts the outer volume
read-write, and the hidden password is used only to read the hidden header
and learn its data region (no hidden keys are retained). A `ProtectedDevice`
then refuses any outer write intersecting that region and latches the whole
volume read-only on the first hit, matching VC's behavior. Verified both
ways in `vault-core/tests/protect_gate.rs`: with protection the overrunning
write is blocked and the hidden tree survives byte-identical; without it the
same write corrupts the hidden volume. The protection failure is a distinct
error (`HiddenVolumeProtected`) so a shell can tell the user their write was
stopped to save the hidden volume, but that message only ever appears to
someone who supplied the hidden password, so it reveals nothing.

### Hidden-volume adjacency (UX rules, all phases)

The UX rules hidden volumes impose hold from 1.0 (doc §11):

- Container contents never enter system-searchable indexes, recents
  surfaces, notification previews, or OS thumbnail caches. Android recents
  thumbnails default off; FLAG_SECURE defaults on for unlock and browser
  screens.
- Probing the hidden-header slot during unlock leaves no trace in logs, UI
  history, or error detail. The "hidden volumes not yet supported" notice
  is worded identically whether or not one was detected... which means it
  must be shown based on *user intent* (they asked), never spontaneously.
  UI copy for anything hidden-volume-adjacent gets reviewed against this
  paragraph.
- Remembered unlock parameters (PRF/scheme cache keyed by salt fingerprint)
  contain no secrets and no evidence of hidden-slot probing. Remembering a
  PIM is opt-in per container because a stored PIM is weak evidence a
  container has a non-default configuration.

## Out of scope: said plainly

- **A compromised OS.** Malware with your session, root, or a hostile
  keyboard/IME can capture your passphrase or read decrypted content. No
  app can defend against the platform it runs on.
- **Screen capture the OS permits.** FLAG_SECURE and its iOS analog reduce
  accidents; they do not stop a platform that chooses to record.
- **Forensic RAM capture** of an unlocked device, and cold-boot-class
  attacks. Locking promptly is the mitigation the app can offer (auto-lock,
  screen-off lock); physics is not.
- **The strength of your passphrase** and VeraCrypt's format-level
  cryptography itself. We implement the format faithfully; we do not claim
  to improve it.
- **Traffic/endpoint observation that a container exists.** VaultPony
  never phones home, but cloud sync apps, backups, and MDM outside our
  process may observe container files themselves.
- **Plausible deniability guarantees.** Until hidden-volume support ships
  (P8/P9), VaultPony makes no deniability claims at all; after it ships,
  claims will be scoped precisely and this section rewritten first.

## Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| User ↔ app | passphrase/PIM entry | no-echo entry, never in argv or shell history (CLI), wiped buffers |
| Platform storage ↔ core | dup'd raw fd via FFI | core never sees platform storage APIs; fd is the only capability |
| Container bytes ↔ core | parser | fuzzed, memory-safe, fail-closed errors |
| Core ↔ shells | UniFFI generated glue | scoped buffers, wipe-after-use, glue audit |
| App ↔ other apps | SAF DocumentsProvider / FileProvider (P11), share sheet | user-initiated only; provider exposes unlocked volumes, never secrets |
| App ↔ OS UI | recents, screenshots, indexes, notifications | FLAG_SECURE default-on, recents thumbnails off, zero indexing |

## Crash and diagnostics policy

No telemetry of any kind. Crash logs are produced locally by the OS only;
in-app "export diagnostics" (if ever added) is user-action-only, and its
output is reviewed against the no-secrets/no-metadata rule before the
feature ships. The support flow is the CLI's `info` output, which contains
format parameters and never names, paths, or key material.

## Standing review gates

- Any new dependency: `cargo-deny` green + a look at what it links
  (anything touching the network is an automatic no).
- Any new `unsafe`: called out in PR description.
- Any new OS-facing surface (provider, extension, intent/URL handler):
  reviewed against the hidden-volume adjacency rules above.
- Any error/log string that can contain user data: rejected in review; the
  error type carries structure, the UI layer decides presentation.
