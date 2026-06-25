# Known issues

## 1. OpenSSL SONAME collision in mixed processes (the migration blocker)

`sk_pgp` works standalone (parse / generate / sign / verify with ML-DSA-87+Ed448
all proven). But it links the Sequoia **`crypto-openssl`** backend against
linuxbrew **OpenSSL 3.6.2** (the only sequoia-openpgp 2.2.0-pqc.1 backend that
implements ML-DSA/ML-KEM — the `rust`, `nettle`, and `botan` backends all return
`false` for the PQC algorithms, confirmed in src/crypto/backend/*/asymmetric.rs).

In a process that has *already* loaded the system `libcrypto.so.3` (e.g. via
psycopg2, requests, …) — which skcomms/skchat/capauth do — the dynamic loader
reuses that already-resident library (SONAME `libcrypto.so.3`) and ignores our
DT_RPATH, so `sk_pgp`'s symbols resolve against the **older system OpenSSL**,
which lacks `OPENSSL_3.4.0` → `ImportError: version 'OPENSSL_3.4.0' not found`.

**Fix (follow-up):** statically link OpenSSL 3.6.2 (with PQC enabled) into the
extension so `sk_pgp` carries its own crypto and never shares `libcrypto.so.3`.
Options to evaluate: the `ossl` crate's static/vendored support; an
`OPENSSL_STATIC=1` + vendored OpenSSL 3.5+ build; or symbol-versioned isolation.
Until then, `sk_pgp` is reliable only in a process that does NOT load a different
system OpenSSL first.
