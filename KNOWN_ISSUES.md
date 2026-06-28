# Known issues

## 1. OpenSSL SONAME collision — ✅ RESOLVED (2026-06-25)

**Was:** PQC is only in Sequoia's `crypto-openssl` backend (the `rust`/`nettle`/
`botan` backends return `false` for ML-DSA/ML-KEM), so `sk_pgp` links OpenSSL
3.6.2 (brew, the PQC-capable one). In a process that already loaded the system
`libcrypto.so.3` (psycopg2/cryptography/requests…), the loader reused the system
lib (no `OPENSSL_3.4.0` symbols) → `ImportError`. skcomms/skchat/capauth all hit this.

**Fix:** ship a **self-contained wheel**. `.cargo/config.toml` bakes the brew
OpenSSL rpath into the extension, so `maturin build --release`'s auditwheel repair
bundles **brew's PQC OpenSSL 3.6.2 under a PRIVATE SONAME** (`libcrypto-<hash>.so.3`,
exporting ML-DSA-65/87 + ML-KEM-768/1024) and rewrites the extension's `DT_NEEDED`
to that private name. No shared `libcrypto.so.3` → no collision. VERIFIED: load
system OpenSSL first, then `sk_pgp` generate/sign/verify — works.

**Build + install (the correct flow — NOT `maturin develop`, NOT a raw wheel):**
```
maturin build --release --interpreter ~/.skenv/bin/python   # auto-repairs w/ rpath → bundles brew libcrypto privately
~/.skenv/bin/pip install --no-deps --force-reinstall target/wheels/sk_pgp-*.whl
```

## 2. Still-stubbed surface (raise `PgpError` by design)

As of 2026-06-28, inline sign/verify (`Key.sign_inline` / `Cert.verify_inline`)
and ML-KEM message crypto (`Cert.encrypt` / `Key.decrypt`) are **real-bound and
tested** (`tests/test_inline_and_kem.py`, incl. a PQC ML-KEM-1024+X448 round-trip).

Two methods remain honest stubs (they raise `PgpError("… not implemented yet")`,
never a fake answer):

- **`Key.add_pqc_subkeys`** — additive, fingerprint-preserving subkey grafting
  (the in-process equivalent of `sq key subkey add`). The sequoia `KeyBuilder` /
  subkey-binding-signature path that preserves the existing primary key was not
  pinned in recon, so it is deliberately not faked. Until then, generate a fresh
  PQC cert with `Key.generate(..., suite="mldsa87-ed448")`.
- **`Cert.rsa_public_numbers` / `Cert.ed25519_public_bytes`** — public-MPI
  extraction for DID/JWK emission (`capauth/did.py`); the exact
  `mpi::PublicKey` access path is still TBD.

These are guarded by `tests/test_smoke.py::test_todo_stubs_raise` so they cannot
silently start returning wrong answers before they are implemented.

### Contract notes (the two new real-bound paths)

- `Cert.verify_inline` deliberately **withholds the message bytes** when the
  signature does not verify (returns `(False, b"")` rather than the unverified
  plaintext) — a caller must never act on data that failed its signature.
- `Key.decrypt` is **decrypt-only**: it does not enforce an inner signature (use
  `verify_inline` / `verify_detached` for authentication).
- Both are **additive** new methods — no existing wire format, no existing test,
  and not the LIVE skchat/skcomms ratchet (which is not PGPy-based) is touched.
