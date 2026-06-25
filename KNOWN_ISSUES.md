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
