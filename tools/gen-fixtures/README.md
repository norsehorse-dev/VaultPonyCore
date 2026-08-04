# gen-fixtures

The compatibility matrix is never hand-maintained (planning doc §4). Two
scripts, one pin:

- `PIN` — the VeraCrypt tag + commit everything is generated from.
- `gen_matrix.py` — parses the pinned checkout (`Crypto.c`, `Pkcs5.c`) and
  emits `core/vc-types/src/registry/generated.rs` plus
  `tools/fixtures/matrix.json`. `--check` verifies committed outputs match
  the source (CI runs this when a checkout is available). Hard-fails on
  anything unexpected: unknown cipher tokens, changed table sizes, missing
  iteration-count cases — upstream changes must surface as reviewed diffs.
- `create_fixtures.py` — drives desktop `veracrypt --text` over
  `matrix.json` to build the fixture corpus + `manifest.json` with
  checksums. Linux + VeraCrypt CLI (+ ntfs-3g for NTFS fixtures) required.

## Regenerating after an upstream release

```
git clone --depth 1 --branch <NEW_TAG> https://github.com/veracrypt/VeraCrypt.git /tmp/vc-src
git -C /tmp/vc-src rev-parse HEAD
```

Update `PIN` with the new tag + commit, then:

```
python3 tools/gen-fixtures/gen_matrix.py --vc-src /tmp/vc-src
```

Review the diff like any code change. If scheme/PRF counts changed, the
script stops and tells you — update its `EXPECTED_*` constants as part of
the same reviewed change, never blindly.

## Known gaps

- Kuznyechik-family schemes are `format_enabled=0` in 1.26.x: the pinned
  CLI mounts them but refuses to create them. Their 30 fixtures need a
  one-time build with an older VeraCrypt (1.25.9) — tracked as `missing`
  in the manifest until then.
- Large (>4 GiB) files inside fixtures are deferred to P5 so the corpus
  stays small enough to cache in CI.
