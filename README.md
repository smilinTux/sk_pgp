# sk_pgp

[![CI](https://github.com/smilinTux/sk_pgp/actions/workflows/ci.yml/badge.svg)](https://github.com/smilinTux/sk_pgp/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776ab.svg)](pyproject.toml)
[![Engine](https://img.shields.io/badge/engine-sequoia--openpgp%202.2.0--pqc.1-orange.svg)](https://gitlab.com/sequoia-pgp/sequoia)
[![Suite](https://img.shields.io/badge/default-mldsa87--ed448%20(NIST%20L5)-1f6feb.svg)](https://github.com/smilinTux/sk-standards)
[![Standards](https://img.shields.io/badge/FIPS-203%20%2F%20204-555.svg)](https://csrc.nist.gov/pubs/fips/204/final)

Sovereign **post-quantum OpenPGP for Python** — PyO3 bindings to the PQC-capable
**sequoia-openpgp** (`=2.2.0-pqc.1`, the exact crate our `sq 1.4.0-pqc.1` was
built from), packaged with **maturin**. It is the sovereign **PGPy / `gpg` 2.4
replacement** for the SK ecosystem's OpenPGP signing surface.

> ⚠️ **Experimental · pre-1.0 · NOT independently security-audited.** This is the
> Python *binding surface* over the vetted **sequoia-openpgp** PQC engine + OpenSSL 3.6
> + liboqs 0.14 — but the package itself has had **no third-party security audit,
> fuzzing, or formal review**. sk_pgp adds **no original cryptography**; the original
> code is the PyO3 wiring. We apply our own honest-claims discipline to the library
> itself: **review it yourself before production use, and don't trust it beyond the
> evidence.** (See [SECURITY.md](SECURITY.md) and [KNOWN_ISSUES.md](KNOWN_ISSUES.md).)

This is the **PGPy replacement**: it can load **v6 / RFC 9580** + **post-quantum**
(ML-DSA / ML-KEM) OpenPGP keys, **sign** (including the **ML-DSA-87 + Ed448** and
**ML-DSA-65 + Ed25519** composites), **verify**, and handle certs — operations
**PGPy and gpg 2.4 cannot do** — in-process, instead of shelling out to `sq`.

Sibling to the [`sk-pqc`](https://github.com/smilinTux/sk-pqc-py) family (hybrid
X25519 + ML-KEM-768 KEM, in Python/Rust/Dart). Where `sk-pqc` does **key
encapsulation**, `sk_pgp` does **OpenPGP identity + signatures** (and, later,
ML-KEM encryption).

```python
import sk_pgp

# Generate a v6/RFC9580 post-quantum keypair (ML-DSA-87 + Ed448, NIST L5).
key  = sk_pgp.Key.generate("Lumina <lumina@skworld.io>", "mldsa87-ed448",
                           password="hunter2")

sig  = key.sign_detached(b"hello world", password="hunter2")  # armored detached sig
cert = key.cert                                               # public half (a sk_pgp.Cert)

assert cert.verify_detached(sig, b"hello world") is True
print(cert.fingerprint)        # 64 hex chars for a v6 key (40 for v4)
print(cert.is_post_quantum)    # True
```

---

## Honest claims (read this)

- These are **post-quantum** / **quantum-resistant** algorithms. They are **not**
  "quantum-proof," "unbreakable," or "quantum-safe." Lattice cryptography is
  young; the defensible words are **"post-quantum"** / **"quantum-resistant."**
- The PQC signing primary is a **hybrid composite** (lattice **ML-DSA** + classical
  **EdDSA**). A signature is valid **iff BOTH legs verify** — sk_pgp never reports
  a partial composite as valid, and the AND-semantics is enforced **inside
  sequoia** for the composite algorithms. We bind sequoia / liboqs; **we never
  hand-roll crypto.**
- Two cipher suites:
  - **`mldsa87-ed448`** — ML-DSA-87 + Ed448 signing, ML-KEM-1024 + X448 encryption
    (FIPS 204 / 203, NIST **L5**). The default.
  - **`mldsa65-ed25519`** — ML-DSA-65 + Ed25519, ML-KEM-768 + X25519 (NIST **L3**).
  - plus classical `cv25519` / `rsa4k` / `rsa3k` for fixtures and compatibility.
- The post-quantum assurance ultimately rests on **sequoia-openpgp** + its
  **crypto-openssl** backend (OpenSSL 3.6.x) + **liboqs 0.14** for the ML-KEM /
  ML-DSA primitives. sk_pgp adds **no** original cryptography — only the Python
  surface.
- v6 / RFC 9580 fingerprints are **64 hex chars** (SHA-256); v4 are 40.

Standards: **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), **FIPS 205** (SLH-DSA),
**RFC 8032** (EdDSA), **RFC 9580** (OpenPGP v6), **draft-ietf-openpgp-pqc**
(composite PQC in OpenPGP).

---

## What it is

A thin, readable Python package (`python/sk_pgp/`) over a Rust extension
(`src/lib.rs`) that wraps sequoia-openpgp. Two classes:

- **`Cert`** — a public certificate: `from_bytes` / `from_armor` / `from_file`,
  `.fingerprint`, `.is_post_quantum`, `.to_armor()` / `.to_bytes()`,
  `.verify_detached(sig, data)`.
- **`Key`** — secret key material: `from_bytes` / `from_file`, `Key.generate(...)`,
  `.cert` (public half), `.fingerprint`, `.is_protected`, `.to_armor()`,
  `.sign_detached(data, password=None)`.

It replaces the `sq`-subprocess `SequoiaBackend` in `capauth` with in-process
calls, and is the migration target for the PGPy call-sites in
`skcomms` / `skchat` / `capauth` (see [`DESIGN.md`](DESIGN.md)).

### Status (0.1.0 — skeleton)

| Operation | State |
|---|---|
| `Cert.from_bytes` / `from_armor` / `from_file` | ✅ real-bound |
| `Cert.fingerprint` / `is_post_quantum` / `has_secret_key` | ✅ real-bound |
| `Cert.to_armor` / `to_bytes` | ✅ real-bound |
| `Cert.verify_detached` | ✅ real-bound |
| `Key.from_bytes` / `from_file` | ✅ real-bound |
| `Key.generate` (PQC + classical, v6/v4) | ✅ real-bound |
| `Key.cert` / `fingerprint` / `is_protected` / `to_armor` | ✅ real-bound |
| `Key.sign_detached` (incl. protected keys) | ✅ real-bound |
| `Key.sign_inline` / `Cert.verify_inline` | ⏳ TODO stub |
| `Cert.encrypt` / `Key.decrypt` (ML-KEM) | ⏳ TODO stub |
| `Key.add_pqc_subkeys` (additive) | ⏳ TODO stub |
| `Cert.rsa_public_numbers` / `ed25519_public_bytes` (DID/JWK) | ⏳ TODO stub |

TODO stubs raise a catchable `sk_pgp.PgpError`; they compile and have the right
shape but are not yet implemented.

---

## Build

`sk_pgp` is a Rust → Python extension built with **maturin**. It pins the PQC
sequoia crate and the **crypto-openssl** backend — exactly how `sq 1.4.0-pqc.1`
was built (linuxbrew OpenSSL 3.6.2 + liboqs 0.14).

```bash
source ~/.cargo/env                                          # rustc 1.96.0
export OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3  # OpenSSL 3.6.2
export BINDGEN_EXTRA_CLANG_ARGS="-I${OPENSSL_DIR}/include"
# liboqs 0.14 at ~/.local/lib/liboqs.so — ensure on the linker/runtime path.

# dev loop (installs into the active venv):
~/.skenv/bin/maturin develop --release
python -c "import sk_pgp; print(sk_pgp.Key.generate('a@b','mldsa87-ed448').fingerprint)"

# distributable wheel (abi3 → ONE wheel for CPython 3.9+):
~/.skenv/bin/maturin build --release   # → target/wheels/sk_pgp-0.1.0-cp39-abi3-*.whl
```

This build links a specific OpenSSL 3.6.2 + liboqs and is **not** manylinux-portable
as-is; per-arch wheels are CI follow-up.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Related projects / See also
- ⬆️ **Depends on:** [sequoia-pgp](https://gitlab.com/sequoia-pgp/sequoia) — the PQC OpenPGP engine `sk_pgp` binds (via PyO3).
- ↔️ **Sibling (Python):** [sk-pqc](https://github.com/smilinTux/sk-pqc-py) ([PyPI](https://pypi.org/project/sk-pqc/)) — hybrid X25519 + ML-KEM-768 **confidentiality** primitives (the encryption counterpart to this signing library).
- ↔️ **Sibling (Rust):** [sk-pqc](https://github.com/smilinTux/sk-pqc-rs) ([crates.io](https://crates.io/crates/sk-pqc)) — the native Rust hybrid-KEM core (full module set + wire formats).
- ↔️ **Sibling (Dart):** [sk_pqc](https://github.com/smilinTux/sk-pqc-dart) ([pub.dev](https://pub.dev/packages/sk_pqc)) — the Dart/Flutter hybrid-KEM companion (web + native).
- ⬇️ **Used by:** [capauth](https://github.com/smilinTux/capauth) — issues the post-quantum signing root through `sk_pgp`; [skcomms](https://github.com/smilinTux/skcomms) / [skchat](https://github.com/smilinTux/skchat) — the signing layers migrating off PGPy onto `sk_pgp`.
- 📐 **Standards:** [sk-standards](https://github.com/smilinTux/sk-standards) — crypto · data-flow · version · doc/SOP.

Where `sk-pqc` does **key encapsulation** (confidentiality), `sk_pgp` does **OpenPGP
identity + signatures** (and, later, ML-KEM message encryption). Together they cover the
SK ecosystem's post-quantum surface.
