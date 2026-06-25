# PyO3 + maturin Packaging Template for `sk_pgp`

**Recon doc** — how to package a Rust → Python extension that binds the
**PQC-capable `sequoia-openpgp 2.2.0-pqc.1`** crate and ships as a Python wheel,
mirroring the proven binding *structure* of the upstream **pysequoia** project.

> **Reference template:** `pysequoia` (Wiktor Kwapisiewicz),
> <https://codeberg.org/wiktor/pysequoia> (mirror: gitlab.com/sequoia-pgp/pysequoia).
> **Important caveat:** released pysequoia is **classical-only** — it pins
> `sequoia-openpgp = "1.14"` with `crypto-nettle`, has **no ML-DSA / ML-KEM / v6**.
> We mirror its PyO3 *binding structure* exactly, but swap the dependency for the
> PQC crate and the crypto backend for OpenSSL. pysequoia also pins the **old
> PyO3 0.18** API (bare `&PyModule`); `sk_pgp` should target **current PyO3
> (0.24+) Bound API** instead — both are shown below, with the modern one preferred.

**Verified ground truth used for this doc (read, not guessed):**
- PQC crate source: `~/.cargo/registry/.../sequoia-openpgp-2.2.0-pqc.1/`
  (confirmed `CipherSuite::MLDSA65_Ed25519`, `CipherSuite::MLDSA87_Ed448`;
  `PublicKeyAlgorithm::{MLDSA65_Ed25519, MLKEM768_X25519, MLDSA87_Ed448, MLKEM1024_X448}`).
- `sequoia-sq 1.4.0-pqc.1` source — reference for how `sq` calls the API.
- `examples/generate-sign-verify.rs` in the PQC crate — canonical keygen / sign / verify flow (quoted below).
- `capauth/src/capauth/crypto/sequoia_backend.py` — the subprocess ops `sk_pgp` must replace in-process.
- pysequoia `Cargo.toml`, `pyproject.toml`, `src/lib.rs`, `src/cert.rs` (fetched).
- maturin installed locally: **`~/.skenv/bin/maturin` → version `1.14.1`** (confirmed).

---

## 1. Project layout

A maturin "mixed" Rust/Python project (Rust core + thin Python wrapper) looks like:

```
sk_pgp/
├── Cargo.toml            # Rust crate manifest ([lib] crate-type = cdylib)
├── pyproject.toml        # Python build config (maturin backend)
├── src/                  # Rust binding source
│   ├── lib.rs            # #[pymodule] entrypoint — wires classes/functions
│   ├── cert.rs           # #[pyclass] Cert (load/serialize/fingerprint)
│   ├── keygen.rs         # generate_keypair() → PQC cert
│   ├── sign.rs           # sign() / verify()
│   └── error.rs          # custom exception + Result→PyErr mapping
├── python/               # (optional) pure-Python wrapper package
│   └── sk_pgp/
│       └── __init__.py   # re-exports the compiled `_sk_pgp` symbols, adds sugar
├── tests/                # pytest
└── README.md
```

Pure-Rust-only layout (no Python wrapper) is simpler: just `Cargo.toml`,
`pyproject.toml`, `src/lib.rs`. The compiled module *is* the importable package.
For `sk_pgp` the **mixed layout is recommended** so the public Python API
(`sk_pgp.generate_keypair(...)`, type hints, docstrings, honesty-ethos wrappers)
lives in readable Python while crypto stays in Rust.

---

## 2. `Cargo.toml`

The two non-negotiable pieces: `crate-type = ["cdylib"]` (so the linker emits a
`.so`/`.pyd` Python can `dlopen`) and the `pyo3` `extension-module` feature.

```toml
[package]
name = "sk_pgp"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"          # sequoia-openpgp 2.2.0-pqc.1 requires >= 1.85
license = "Apache-2.0"
description = "Sovereign post-quantum OpenPGP for Python — PyO3 bindings to PQC sequoia-openpgp"
publish = false                # wheels ship to PyPI; the Rust crate is not published to crates.io

# THE critical bit: build a C-ABI dynamic lib that Python can import.
[lib]
name = "_sk_pgp"               # compiled module name (import as sk_pgp._sk_pgp in mixed layout)
crate-type = ["cdylib"]

[dependencies]
# PyO3 with the Python-extension features.
#   extension-module : link against libpython at runtime, not build time (required for wheels)
#   abi3-py39        : build ONE stable-ABI wheel that works on CPython 3.9+ (no per-version rebuild)
#   anyhow           : auto-convert anyhow::Error -> PyErr via `?`
pyo3 = { version = "0.24", features = ["extension-module", "abi3-py39", "anyhow"] }

# The POST-QUANTUM OpenPGP engine. NOTE the exact pinned PQC pre-release.
#   default-features = false + crypto-openssl  ==  exactly how `sq 1.4.0-pqc.1` was built
#   (linuxbrew OpenSSL 3.6.2 provider). DO NOT enable crypto-nettle (no PQC there).
sequoia-openpgp = { version = "=2.2.0-pqc.1", default-features = false, features = ["crypto-openssl", "compression"] }

anyhow = "1"

# Pin the PQC pre-release precisely. Cargo will not pick a -pqc.1 pre-release
# without an explicit `=` requirement, and the crate is sourced from the local
# registry cache / a patched index.
[patch.crates-io]
# (if pulling from a vendored path instead of the registry cache, point it here)
# sequoia-openpgp = { path = "../vendor/sequoia-openpgp-2.2.0-pqc.1" }
```

**abi3 vs. non-abi3.** `abi3-py39` is strongly recommended: it produces a single
`cp39-abi3` wheel importable on every CPython ≥ 3.9, instead of one wheel per
minor version. The cost is the `abi3` subset of the C-API; PyO3 handles this
transparently. (pysequoia does *not* use abi3 — it builds per-version — but
`sk_pgp` should, to cut the build matrix.)

**Build environment** (matches the `sq` PQC build; export before `maturin build`):

```bash
source ~/.cargo/env                                   # rustc 1.96.0
export OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3   # OpenSSL 3.6.2
export BINDGEN_EXTRA_CLANG_ARGS="-I${OPENSSL_DIR}/include"
# liboqs 0.14 at ~/.local/lib/liboqs.so — ensure on the linker/runtime path if the
# OpenSSL provider dlopen's the OQS provider for ML-KEM/ML-DSA primitives.
```

---

## 3. `pyproject.toml` — maturin as the build backend

```toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "sk_pgp"
description = "Sovereign post-quantum OpenPGP library for Python (PyO3 + sequoia-openpgp PQC)"
requires-python = ">=3.9"
license = "Apache-2.0"
keywords = ["openpgp", "pgp", "post-quantum", "pqc", "ml-dsa", "ml-kem", "sequoia"]
authors = [{ name = "smilinTux / SKWorld" }]
classifiers = [
  "Programming Language :: Rust",
  "Programming Language :: Python :: Implementation :: CPython",
  "License :: OSI Approved :: Apache Software License",
]
dynamic = ["version"]            # version comes from Cargo.toml via maturin

[project.urls]
Homepage = "https://github.com/smilinTux/sk_pgp"
Repository = "https://github.com/smilinTux/sk_pgp"

# maturin-specific knobs.
[tool.maturin]
# Mixed layout: pure-Python sources live under python/, compiled ext is added in.
python-source = "python"
# The Rust ext is exposed as a submodule of the package (sk_pgp._sk_pgp);
# python/sk_pgp/__init__.py re-exports its symbols.
module-name = "sk_pgp._sk_pgp"
# Build the abi3 wheel (must agree with the abi3-py39 Cargo feature).
features = ["pyo3/extension-module"]
# Pass crypto build flags through if not set in the environment:
# (env vars above are simpler than baking these in)
```

> If `sk_pgp` is **pure-Rust** (no `python/` dir), drop `python-source` and set
> `module-name = "sk_pgp"`; the compiled `.so` becomes the top-level package.

The `build-backend = "maturin"` line is what lets `pip install .`, `pip wheel`,
and `python -m build` drive maturin automatically.

---

## 4. `src/lib.rs` — the `#[pymodule]` entrypoint

This mirrors pysequoia's `src/lib.rs` wiring (it exposes `Cert`/`KeyServer`/… as
classes and `sign`/`encrypt`/`decrypt` as functions), modernized to the Bound API.

```rust
use pyo3::prelude::*;

mod cert;
mod keygen;
mod sign;
mod error;            // custom exception lives here

/// The compiled module. Function name MUST equal the [lib] name (`_sk_pgp`),
/// unless overridden with #[pyo3(name = "...")].
#[pymodule]
fn _sk_pgp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes (wrap Rust structs as Python objects).
    m.add_class::<cert::Cert>()?;

    // Free functions.
    m.add_function(wrap_pyfunction!(keygen::generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign::sign, m)?)?;
    m.add_function(wrap_pyfunction!(sign::verify, m)?)?;

    // Register the custom exception type so Python can `except sk_pgp.PgpError`.
    m.add("PgpError", m.py().get_type::<error::PgpError>())?;

    // Module constants — the two PQC cipher suites we support.
    m.add("CIPHER_MLDSA87_ED448", "mldsa87-ed448")?;   // L5  (ML-DSA-87 + Ed448 / ML-KEM-1024 + X448)
    m.add("CIPHER_MLDSA65_ED25519", "mldsa65-ed25519")?; // L3 (ML-DSA-65 + Ed25519 / ML-KEM-768 + X25519)
    Ok(())
}
```

> **PyO3 0.18 (pysequoia, legacy) form**, for comparison — note bare `&PyModule`
> and `_py: Python`:
> ```rust
> #[pymodule]
> fn pysequoia(_py: Python, m: &PyModule) -> PyResult<()> {
>     m.add_class::<cert::Cert>()?;
>     m.add_function(wrap_pyfunction!(sign::sign, m)?)?;
>     Ok(())
> }
> ```
> Use the **Bound** form (`&Bound<'_, PyModule>`) for new code.

---

## 5. `src/error.rs` — Rust `Result`/`Err` → Python exception

The clean pattern: define one custom exception with `create_exception!`, then
convert `anyhow::Error` into it. With the `pyo3/anyhow` feature, `?` on an
`anyhow::Result` already yields a `PyRuntimeError` for free — but a *named*
exception (`sk_pgp.PgpError`) gives callers something specific to catch.

```rust
use pyo3::create_exception;
use pyo3::exceptions::PyException;

// Defines a Python exception class `PgpError` subclassing Exception.
create_exception!(_sk_pgp, PgpError, PyException, "Error from the sk_pgp OpenPGP engine.");

/// Map any error type into our Python exception.
pub fn to_py_err<E: std::fmt::Display>(e: E) -> pyo3::PyErr {
    PgpError::new_err(e.to_string())
}
```

Usage in a binding method — three equivalent idioms:

```rust
// (a) explicit map_err -> named exception (clearest):
let cert = openpgp::Cert::from_bytes(data).map_err(error::to_py_err)?;

// (b) with pyo3/anyhow feature, `?` on anyhow::Result auto-converts to PyRuntimeError:
let cert = openpgp::Cert::from_bytes(data)?;   // anyhow::Error -> PyErr automatically

// (c) raise directly:
if !verified {
    return Err(error::PgpError::new_err("signature did not verify"));
}
```

Any `PyResult<T>` that is `Err(PyErr)` is **raised as a Python exception** when the
call returns to Python. This is the whole error-bridging contract.

---

## 6. `src/cert.rs` — `#[pyclass]` / `#[pymethods]`, bytes & strings

Mirrors pysequoia's `Cert` (which uses `#[staticmethod]` factories `from_bytes` /
`from_file` / `generate` rather than `#[new]`, and `__str__` for armor). Modernized
to Bound + the PQC crate.

```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

use crate::error::to_py_err;

#[pyclass]
#[derive(Clone)]
pub struct Cert {
    pub(crate) cert: openpgp::Cert,
}

#[pymethods]
impl Cert {
    /// Parse a cert from raw OpenPGP bytes (armored or binary).
    /// Accepting `&[u8]` lets Python pass `bytes`, `bytearray`, or memoryview.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(data).map_err(to_py_err)?;
        Ok(Cert { cert })
    }

    /// Parse from an ASCII-armored string.
    #[staticmethod]
    fn from_armor(armor: &str) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(armor.as_bytes()).map_err(to_py_err)?;
        Ok(Cert { cert })
    }

    /// Return the binary (non-armored) serialization as Python `bytes`.
    /// PyBytes::new(py, &buf) builds a Bound<'py, PyBytes>; returning it hands
    /// Python an immutable `bytes` object.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut buf = Vec::new();
        self.cert.serialize(&mut buf).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &buf))
    }

    /// ASCII-armored serialization, as a Python `str`.
    fn to_armor(&self) -> PyResult<String> {
        let mut buf = Vec::new();
        self.cert.armored().serialize(&mut buf).map_err(to_py_err)?;
        String::from_utf8(buf).map_err(to_py_err)
    }

    /// v6 (RFC 9580) fingerprints are 64 hex chars; v4 are 40.
    #[getter]
    fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    /// `str(cert)` → armored cert (pysequoia convention).
    fn __str__(&self) -> PyResult<String> {
        self.to_armor()
    }
}
```

**Bytes/string mapping cheat-sheet**

| Direction        | Rust type (param/return)              | Python type     |
|------------------|---------------------------------------|-----------------|
| bytes in         | `&[u8]`                               | `bytes` / `bytearray` / memoryview |
| bytes out        | `Bound<'py, PyBytes>` (`PyBytes::new(py, &v)`) | `bytes`  |
| str in           | `&str` / `String`                     | `str`           |
| str out          | `String`                              | `str`           |
| optional         | `Option<T>`                           | `T` or `None`   |

---

## 7. `src/keygen.rs` and `src/sign.rs` — the PQC ops (from verified sources)

These wrap the exact API calls confirmed in the PQC crate's
`examples/generate-sign-verify.rs` and the `CipherSuite` enum in
`src/cert/builder.rs`. They replace the `sq` subprocess calls currently in
`capauth/.../sequoia_backend.py` with in-process calls.

```rust
// keygen.rs — PQC keypair generation (replaces `sq key generate --profile rfc9580`)
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::cert::CipherSuite;
use crate::cert::Cert;
use crate::error::to_py_err;

#[pyfunction]
#[pyo3(signature = (user_id, cipher_suite="mldsa87-ed448"))]
fn generate_keypair(user_id: &str, cipher_suite: &str) -> PyResult<Cert> {
    // Map our string suite names → the verified PQC CipherSuite variants.
    let suite = match cipher_suite {
        "mldsa87-ed448"   => CipherSuite::MLDSA87_Ed448,    // L5, RFC9580/v6
        "mldsa65-ed25519" => CipherSuite::MLDSA65_Ed25519,  // L3
        "cv25519"         => CipherSuite::Cv25519,          // classical fallback
        other => return Err(to_py_err(format!("unknown cipher suite: {other}"))),
    };
    let (cert, _rev) = CertBuilder::new()
        .set_cipher_suite(suite)          // selects v6/RFC9580 profile for PQC suites
        .add_userid(user_id)
        .add_signing_subkey()
        .generate()
        .map_err(to_py_err)?;
    Ok(Cert { cert })
}
```

```rust
// sign.rs — detached/inline sign + verify (replaces `sq sign` / `sq verify`)
// Flow taken verbatim-in-structure from examples/generate-sign-verify.rs:
//   keys().unencrypted_secret().with_policy(p,None).supported().alive()
//        .revoked(false).for_signing().next().key().into_keypair()
//   Message::new -> Signer::new -> LiteralWriter -> write_all -> finalize
//   VerifierBuilder::from_bytes(...).with_policy(p, None, helper) + VerificationHelper
// (See doc body / the crate example for the full Helper impl.)
```

> The verify side requires a `VerificationHelper` (`get_certs` + `check`); the
> **hybrid composite signature is valid iff BOTH legs (ML-DSA + classical)
> verify** — sequoia enforces this internally for the composite algorithms, so
> the binding just returns the boolean/raises on `Some(Err(_))`. We never
> hand-roll the composite check.

---

## 8. Building wheels — `maturin build` / `maturin develop`

`~/.skenv/bin/maturin` is installed (**v1.14.1**, confirmed). Commands:

```bash
# Always set the crypto build env first (section 2).
source ~/.cargo/env
export OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3
export BINDGEN_EXTRA_CLANG_ARGS="-I${OPENSSL_DIR}/include"

# --- dev loop: compile the ext and install it into the ACTIVE venv in-place ---
~/.skenv/bin/maturin develop            # debug build, editable-ish install
~/.skenv/bin/maturin develop --release  # optimized (do this for crypto perf)
# now: python -c "import sk_pgp; print(sk_pgp.generate_keypair('a@b', 'mldsa87-ed448'))"

# --- produce a distributable wheel ---
~/.skenv/bin/maturin build --release    # writes target/wheels/sk_pgp-0.1.0-cp39-abi3-*.whl
# abi3 → ONE wheel for CPython 3.9+ ; without abi3 you get one wheel per minor.

# --- install the built wheel ---
~/.skenv/bin/pip install target/wheels/sk_pgp-0.1.0-*.whl

# --- sdist (source dist; consumers compile Rust at install time) ---
~/.skenv/bin/maturin sdist

# --- PyPI publish (Apache-2.0, public) ---
~/.skenv/bin/maturin publish            # build + upload; or `twine upload target/wheels/*`
```

- `maturin develop` = fast inner loop: builds into the current virtualenv so
  `import sk_pgp` works immediately. **Requires an active venv** (it installs into
  `sys.prefix`); run it from inside `~/.skenv` or another venv.
- `maturin build` = produce wheel artifacts under `target/wheels/` without
  installing. Add `--release` for optimized crypto.
- For broad-compat manylinux wheels use `maturin build --release` inside the
  `ghcr.io/pyo3/maturin` manylinux container (or `--manylinux off` /
  `--compatibility linux` for local-only, since this build links a specific
  OpenSSL 3.6.2 and liboqs and is **not** manylinux-portable as-is).
- `pip install .` / `python -m build` also work because `build-backend = "maturin"`.

---

## 9. Honesty ethos (carry into the README, like `sk_pqc`)

- Say **"post-quantum"** / **"quantum-resistant"**, **never "quantum-proof."**
- A **hybrid composite signature is valid iff BOTH legs verify** (ML-DSA *and* the
  classical Ed448/Ed25519 leg). `sk_pgp` binds sequoia + liboqs; it **never
  hand-rolls crypto**.
- Cite the standards: **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), **FIPS 205**
  (SLH-DSA), **RFC 8032** (EdDSA), **RFC 9580** (OpenPGP v6),
  **draft-ietf-openpgp-pqc** (PQC in OpenPGP).
- This is the **PGPy replacement**: v6/RFC9580 + PQC keygen, ML-DSA sign, verify,
  cert handling — operations PGPy and gpg 2.4 cannot do — exposed in-process to
  `skcomms` / `skchat` / `capauth` instead of shelling out to `sq`.

---

## Sources

- [pysequoia — Cargo.toml / pyproject.toml / src/lib.rs / src/cert.rs](https://codeberg.org/wiktor/pysequoia) (mirror gitlab.com/sequoia-pgp/pysequoia) — binding-structure reference (classical-only, PyO3 0.18).
- [PyO3 user guide — functions & module wiring (0.24)](https://pyo3.rs/v0.24.0/function/signature.html)
- [docs.rs — pyo3 PyBytes (Bound API)](https://docs.rs/pyo3/latest/pyo3/types/struct.PyBytes.html)
- Local: `sequoia-openpgp-2.2.0-pqc.1/` (`src/cert/builder.rs`, `examples/generate-sign-verify.rs`), `sequoia-sq-1.4.0-pqc.1/`, `capauth/src/capauth/crypto/sequoia_backend.py`.
