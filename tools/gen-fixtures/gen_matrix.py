#!/usr/bin/env python3
"""Generate the cipher/PRF registry and CI fixture matrix from a pinned
VeraCrypt source checkout (planning doc §4: do not hand-maintain the matrix).

Reads:
  src/Common/Crypto.c   -> EncryptionAlgorithms[] (schemes, layer order,
                           FormatEnabled) and Hashes[] (PRF names, order)
  src/Common/Pkcs5.c    -> get_pkcs5_iteration_count() non-boot defaults

Emits:
  core/vc-types/src/registry/generated.rs   (Rust registry table)
  tools/fixtures/matrix.json                (CI fixture matrix)

Usage:
  gen_matrix.py --vc-src /path/to/VeraCrypt          regenerate outputs
  gen_matrix.py --vc-src /path/to/VeraCrypt --check  fail if outputs drift
  gen_matrix.py --check                              CI drift check; skips
                                                     with exit 0 + warning if
                                                     no checkout is available

The checkout must match tools/gen-fixtures/PIN (tag + commit); the script
verifies this so "regenerated from the wrong tree" can't happen silently.
Upstream changes then surface as ordinary diffs in code review.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PIN_FILE = Path(__file__).resolve().parent / "PIN"
RUST_OUT = REPO_ROOT / "core" / "vc-types" / "src" / "registry" / "generated.rs"
MATRIX_OUT = REPO_ROOT / "tools" / "fixtures" / "matrix.json"

# C token -> (display fragment, Rust variant). The display name of a cascade
# is built outermost-first: layers [TWOFISH, AES] (innermost-first, as the C
# table is ordered) renders as "AES(Twofish)".
CIPHER_TOKENS = {
    "AES": ("AES", "Cipher::Aes"),
    "SERPENT": ("Serpent", "Cipher::Serpent"),
    "TWOFISH": ("Twofish", "Cipher::Twofish"),
    "CAMELLIA": ("Camellia", "Cipher::Camellia"),
    "KUZNYECHIK": ("Kuznyechik", "Cipher::Kuznyechik"),
}

# Expected shape for VeraCrypt 1.26.x. If parsing yields anything else,
# upstream changed the format surface — that is a finding, not a nuisance,
# so the script fails loudly rather than emitting a surprise.
EXPECTED_SCHEME_COUNT = 15
EXPECTED_PRF_COUNT = 5

# Try-order for the unlock search (doc §6): SHA-512 first. This is ours, not
# upstream's; it is applied to the parsed PRF list by name.
PRF_POPULARITY = ["SHA-512", "SHA-256", "BLAKE2s-256", "Whirlpool", "Streebog"]


def die(msg: str) -> "NoReturn":
    print(f"gen_matrix: ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def read_pin():
    parts = PIN_FILE.read_text().split()
    if len(parts) != 2:
        die(f"{PIN_FILE} must contain: <tag> <commit>")
    return parts[0], parts[1]


def verify_pin(vc_src: Path):
    tag, commit = read_pin()
    try:
        head = subprocess.run(
            ["git", "-C", str(vc_src), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        die(f"{vc_src} is not a git checkout; cannot verify against PIN")
    if head != commit:
        die(
            f"checkout at {vc_src} is {head[:12]}, but PIN says {tag} "
            f"({commit[:12]}). Update PIN deliberately or fix the checkout."
        )
    return tag, commit


def strip_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def parse_schemes(crypto_c: str):
    """Parse the non-boot EncryptionAlgorithms[] table."""
    m = re.search(
        r"static\s+EncryptionAlgorithm\s+EncryptionAlgorithms\[\]\s*=\s*\{(.*?)\n\};",
        crypto_c, re.S,
    )
    if not m:
        die("EncryptionAlgorithms[] not found in Crypto.c")
    body = m.group(1)
    # Keep only the non-boot section (up to the TC_WINDOWS_BOOT #else).
    body = body.split("#else")[0]

    schemes = []
    row_re = re.compile(
        r"\{\s*\{\s*([A-Z_]+(?:\s*,\s*[A-Z_]+)*)\s*,\s*0\s*\}\s*,"  # ciphers
        r"\s*\{\s*XTS\s*,\s*0\s*\}\s*,"                              # modes
        r"\s*(\d+)\s*,\s*(\d+)\s*\}"                                 # flags
    )
    for row in row_re.finditer(body):
        tokens = [t.strip() for t in row.group(1).split(",")]
        unknown = [t for t in tokens if t not in CIPHER_TOKENS]
        if unknown:
            die(f"unknown cipher token(s) {unknown} — extend CIPHER_TOKENS deliberately")
        # VeraCrypt displays cascades nested outermost-first: the C row
        # {SERPENT, TWOFISH, AES} (innermost-first) is "AES(Twofish(Serpent))".
        outermost_first = [CIPHER_TOKENS[t][0] for t in reversed(tokens)]
        display = "(".join(outermost_first) + ")" * (len(tokens) - 1)
        schemes.append({
            "name": display,
            "tokens": tokens,                      # innermost-first
            "layers": [CIPHER_TOKENS[t][1] for t in tokens],
            "key_bytes": 64 * len(tokens),
            "format_enabled": row.group(2) == "1", # can stock VC create it?
        })
    return schemes


def parse_prfs(crypto_c: str, pkcs5_c: str):
    """Parse Hashes[] for names/order and Pkcs5.c for non-boot defaults."""
    m = re.search(r"static\s+Hash\s+Hashes\[\]\s*=\s*\{(.*?)\n\};", crypto_c, re.S)
    if not m:
        die("Hashes[] not found in Crypto.c")
    hashes = re.findall(
        r'\{\s*([A-Z0-9_]+)\s*,\s*L"([^"]+)"\s*,\s*(TRUE|FALSE)\s*,\s*(TRUE|FALSE)\s*\}',
        m.group(1),
    )
    if not hashes:
        die("no rows parsed from Hashes[]")

    fn = re.search(
        r"int\s+get_pkcs5_iteration_count\s*\([^)]*\)\s*\{(.*?)\n\}",
        pkcs5_c, re.S,
    )
    if not fn:
        die("get_pkcs5_iteration_count not found in Pkcs5.c")
    cases = dict(re.findall(r"case\s+([A-Z0-9_]+)\s*:(.*?)break\s*;", fn.group(1), re.S))

    prfs = []
    for token, name, deprecated, _sysenc in hashes:
        if deprecated == "TRUE":
            continue  # legacy PRFs are a non-goal (doc §2)
        block = cases.get(token)
        if block is None:
            die(f"no iteration-count case for PRF token {token}")
        # Style A: iteration_count = (pim == 0) ? N : ...
        m_a = re.search(r"\(pim\s*==\s*0\)\s*\?\s*(\d+)", block)
        # Style B: if (pim == 0) iteration_count = bBoot ? BOOT : NONBOOT;
        m_b = re.search(r"pim\s*==\s*0.*?bBoot\s*\?\s*\d+\s*:\s*(\d+)", block, re.S)
        if m_a:
            default_iters = int(m_a.group(1))
        elif m_b:
            default_iters = int(m_b.group(1))
        else:
            die(f"could not extract non-boot pim==0 iterations for {token}")
        prfs.append({"name": name, "token": token, "default_iterations": default_iters})

    order = {n: i for i, n in enumerate(PRF_POPULARITY)}
    unknown = [p["name"] for p in prfs if p["name"] not in order]
    if unknown:
        die(f"PRF(s) {unknown} missing from PRF_POPULARITY — rank them deliberately")
    prfs.sort(key=lambda p: order[p["name"]])
    for i, p in enumerate(prfs):
        p["popularity_rank"] = i
    return prfs


def render_rust(schemes, prfs, tag) -> str:
    lines = [
        "// @generated by tools/gen-fixtures/gen_matrix.py — DO NOT EDIT BY HAND.",
        f"// Source of truth: pinned VeraCrypt checkout {tag} (tools/gen-fixtures/PIN).",
        "// Rerun the generator after bumping the pin; review the diff like any code.",
        "//",
        '// Layer order in `layers` is innermost-first: "AES(Twofish)" means Twofish',
        "// is applied to the plaintext first, then AES. Verify against fixtures",
        "// before the first data-path test (vc-types/src/registry.rs note).",
        "",
        "use super::{Cipher, EncryptionScheme, Prf};",
        "",
        "pub static ENCRYPTION_SCHEMES: &[EncryptionScheme] = &[",
    ]
    for s in schemes:
        layers = ", ".join(s["layers"])
        lines.append(
            f'    EncryptionScheme {{ name: "{s["name"]}", layers: &[{layers}] }},'
        )
    lines += ["];", "", "pub static PRFS: &[Prf] = &["]
    for p in prfs:
        iters = f"{p['default_iterations']:_}"
        lines.append(
            f'    Prf {{ name: "{p["name"]}", default_iterations: {iters}, '
            f'popularity_rank: {p["popularity_rank"]} }},'
        )
    lines += ["];", ""]
    return "\n".join(lines)


def build_fixture_list(schemes, prfs):
    """Enumerate the fixture corpus (doc §13): full scheme x PRF coverage on
    the default geometry, plus focused axis sweeps on the default scheme.
    Target is ~100-150 containers; every entry is one container."""
    fixtures = []

    def add(scheme, prf, fs="FAT", sector=512, pim=0, hidden=False):
        fid = "-".join([
            re.sub(r"[^A-Za-z0-9]+", "_", scheme["name"]).strip("_").lower(),
            re.sub(r"[^A-Za-z0-9]+", "_", prf["name"]).strip("_").lower(),
            fs.lower(), str(sector),
            f"pim{pim}", "hidden" if hidden else "plain",
        ])
        fixtures.append({
            "id": fid,
            "scheme": scheme["name"],
            "prf": prf["name"],
            "filesystem": fs,
            "sector_size": sector,
            "pim": pim,
            "hidden": hidden,
            # Stock VC CLI refuses creation for format_enabled=0 schemes
            # (Kuznyechik family in 1.26.x); those need a legacy VC build.
            "creatable_with_pinned_vc": scheme["format_enabled"],
            "size_mib": 16 if fs != "NTFS" else 20,
            "password": "vaultpony-fixture",
        })

    default_scheme = schemes[0]           # AES
    default_prf = prfs[0]                 # SHA-512

    # 1. Full scheme x PRF sweep on default geometry: 15 x 5 = 75.
    for s in schemes:
        for p in prfs:
            add(s, p)

    # 2. Filesystem sweep on AES/SHA-512: covers exFAT + NTFS (created RW
    #    by desktop VC; we only ever read them). No 4096-sector fixtures:
    #    file containers are always 512-byte-sector (the CLI has no
    #    --sector-size; 4096 occurs only on device-hosted volumes, which
    #    are v2 scope). The header parser still accepts both sizes and the
    #    data path uses 512-byte XTS units regardless (doc S6).
    for fs in ["exFAT", "NTFS"]:
        add(default_scheme, default_prf, fs=fs)

    # 3. PIM coverage: nonzero PIM on each PRF (pim=485 -> 500k, a nice
    #    round-trip check on the schedule), plus a high-PIM outlier.
    for p in prfs:
        add(default_scheme, p, pim=485)
    add(default_scheme, default_prf, pim=2000)

    # 4. Hidden volumes (P8 targets; probed-but-refused before that): default
    #    combo plus one cascade, one alternate PRF, one on exFAT.
    add(default_scheme, default_prf, hidden=True)
    add(schemes[6] if len(schemes) > 6 else default_scheme, default_prf, hidden=True)
    add(default_scheme, prfs[1], hidden=True)
    add(default_scheme, default_prf, fs="exFAT", hidden=True)

    ids = [f["id"] for f in fixtures]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        die(f"duplicate fixture ids: {sorted(dupes)}")
    return fixtures


def render_matrix(schemes, prfs, tag, commit) -> str:
    fixtures = build_fixture_list(schemes, prfs)
    doc = {
        "_comment": "Generated by tools/gen-fixtures/gen_matrix.py — do not hand-edit.",
        "veracrypt_pin": {"tag": tag, "commit": commit},
        "schemes": [
            {k: s[k] for k in ["name", "tokens", "key_bytes", "format_enabled"]}
            for s in schemes
        ],
        "prfs": [
            {k: p[k] for k in ["name", "token", "default_iterations", "popularity_rank"]}
            for p in prfs
        ],
        "pim_schedule": {"base": 15000, "per_unit": 1000},
        "fixture_count": len(fixtures),
        "fixtures": fixtures,
    }
    return json.dumps(doc, indent=2) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vc-src", type=Path, help="pinned VeraCrypt checkout")
    ap.add_argument("--check", action="store_true",
                    help="verify committed outputs match; write nothing")
    args = ap.parse_args()

    if args.vc_src is None:
        if args.check:
            # CI convenience: drift check is a no-op without a checkout.
            print("gen_matrix: no --vc-src given; skipping drift check")
            return
        ap.error("--vc-src is required to regenerate")

    tag, commit = verify_pin(args.vc_src)
    crypto_c = strip_block_comments(
        (args.vc_src / "src/Common/Crypto.c").read_text(errors="replace"))
    pkcs5_c = strip_block_comments(
        (args.vc_src / "src/Common/Pkcs5.c").read_text(errors="replace"))

    schemes = parse_schemes(crypto_c)
    prfs = parse_prfs(crypto_c, pkcs5_c)

    if len(schemes) != EXPECTED_SCHEME_COUNT:
        die(f"parsed {len(schemes)} schemes, expected {EXPECTED_SCHEME_COUNT} — "
            f"upstream changed; update EXPECTED_* and review:\n"
            + "\n".join(s["name"] for s in schemes))
    if len(prfs) != EXPECTED_PRF_COUNT:
        die(f"parsed {len(prfs)} PRFs, expected {EXPECTED_PRF_COUNT} — "
            f"upstream changed; update EXPECTED_* and review:\n"
            + "\n".join(p["name"] for p in prfs))

    rust = render_rust(schemes, prfs, tag)
    matrix = render_matrix(schemes, prfs, tag, commit)

    if args.check:
        ok = True
        for path, want in [(RUST_OUT, rust), (MATRIX_OUT, matrix)]:
            have = path.read_text() if path.exists() else "<missing>"
            if have != want:
                ok = False
                print(f"gen_matrix: DRIFT in {path.relative_to(REPO_ROOT)}",
                      file=sys.stderr)
        if not ok:
            die("committed outputs do not match the pinned source; "
                "rerun gen_matrix.py and commit the diff")
        print("gen_matrix: outputs match pinned source")
        return

    MATRIX_OUT.parent.mkdir(parents=True, exist_ok=True)
    RUST_OUT.write_text(rust)
    MATRIX_OUT.write_text(matrix)
    print(f"gen_matrix: wrote {RUST_OUT.relative_to(REPO_ROOT)}")
    print(f"gen_matrix: wrote {MATRIX_OUT.relative_to(REPO_ROOT)} "
          f"({json.loads(matrix)['fixture_count']} fixtures)")


if __name__ == "__main__":
    main()
