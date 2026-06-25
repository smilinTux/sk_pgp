# sk_pgp — Design

Sovereign post-quantum OpenPGP for Python. PyO3 → `sequoia-openpgp 2.2.0-pqc.1`
(crypto-openssl) + maturin. This document is the spec: the Python API, the Rust
binding plan, the test plan, and the (additive) migration off PGPy.

Honesty ethos (carried verbatim into every surface): **post-quantum /
quantum-resistant, never quantum-proof**. A hybrid composite signature is valid
**iff both legs** (ML-DSA + classical EdDSA) verify; sequoia enforces this for
the composite algorithms and we bind it — we never hand-roll crypto. Cite
FIPS 203/204/205, RFC 8032, RFC 9580, draft-ietf-openpgp-pqc.

---

## 1. Python API spec

Modeled on the *actual* PGPy/`sq` usage across `skcomms`/`skchat`/`capauth`
(recon: `docs/recon/pgpy-callsites.md`). The entire PGPy surface in use reduces
to 8 operations; sk_pgp exposes them across two classes plus a backend facade.

### 1.1 `Cert` — public certificate

```python
class Cert:
    @staticmethod
    def from_bytes(data: bytes) -> "Cert"       # armored or binary (auto-detect)
    @staticmethod
    def from_armor(armor: str) -> "Cert"
    @staticmethod
    def from_file(path: str) -> "Cert"

    fingerprint: str        # property — UPPER hex, no spaces; 40 (v4) / 64 (v6)
    is_post_quantum: bool    # property — has an ML-DSA/ML-KEM component
    has_secret_key: bool     # property — is_tsk()

    def to_armor(self) -> str
    def to_bytes(self) -> bytes
    def verify_detached(self, sig: bytes, data: bytes) -> bool

    # DID/JWK (capauth/did.py) — TODO:
    def rsa_public_numbers(self) -> tuple[int, int]
    def ed25519_public_bytes(self) -> bytes
    # message crypto — TODO:
    def encrypt(self, plaintext: bytes, cipher: str = "AES256") -> bytes
    def verify_inline(self, signed: bytes) -> tuple[bool, bytes]
```

### 1.2 `Key` — secret key material

```python
class Key:
    @staticmethod
    def from_bytes(data: bytes) -> "Key"        # raises if no secret material
    @staticmethod
    def from_file(path: str) -> "Key"
    @staticmethod
    def generate(userid: str,
                 suite: str = "mldsa87-ed448",  # | mldsa65-ed25519 | cv25519 | rsa4k | rsa3k
                 password: str | None = None,
                 profile: str = "rfc9580") -> "Key"   # | rfc4880

    cert: "Cert"            # property — public half (strip_secret_key_material)
    fingerprint: str         # property
    is_post_quantum: bool
    is_protected: bool       # property — any secret is passphrase-encrypted

    def to_armor(self) -> str
    def sign_detached(self, data: bytes, password: str | None = None) -> bytes

    # TODO:
    def sign_inline(self, data: bytes, password: str | None = None) -> bytes
    def decrypt(self, ciphertext: bytes, password: str | None = None) -> bytes
    def add_pqc_subkeys(self, password: str | None = None,
                        cipher_suite: str = "mldsa87-ed448") -> "Key"
```

### 1.3 Error / honesty semantics

- One named exception, `sk_pgp.PgpError` (subclass of `Exception`). Malformed
  armor/inputs raise it; callers can `except sk_pgp.PgpError`.
- `verify_detached` **never raises on a bad signature** — it returns `False`
  (capauth/skchat paths `return False` on failure). It raises only on malformed
  signature *bytes*.
- Fingerprints are returned **normalized** (UPPER, no spaces) so callers can drop
  the `.replace(" ","").upper()` dance over time. Both v4 (40-hex) and v6/RFC9580
  (64-hex) are supported.
- TODO stubs raise `PgpError("… not implemented yet (skeleton TODO)")` — catchable,
  never a panic across the FFI boundary.

### 1.4 capauth backend facade (Phase 1 target, not in 0.1.0)

A `CryptoBackend`-shaped adapter so capauth registers it beside
`PGPyBackend` / `SequoiaBackend` with **zero call-site changes**:

```python
class SkPgpBackend(CryptoBackend):
    def available(self) -> bool
    def generate_keypair(name, email, passphrase, algorithm) -> KeyBundle
    def sign(data, private_key_armor, passphrase) -> str
    def verify(data, signature_armor, public_key_armor) -> bool
    def fingerprint_from_armor(key_armor) -> str
    def add_pqc_subkeys(private_key_armor, passphrase, cipher_suite) -> KeyBundle
```

It composes the primitives above (`Key.from_bytes(...).sign_detached(...)`,
`Cert.from_bytes(...).verify_detached(...)`, `Key.generate(...)`), returning
capauth's `KeyBundle(fingerprint, public_armor, private_armor, algorithm)`.

---

## 2. Rust binding plan

Source: `src/lib.rs` (single `#[pymodule] _sk_pgp`). Crate: `cdylib` named
`_sk_pgp`; mixed maturin layout re-exports it as `sk_pgp._sk_pgp`. Every symbol
below is read from the cached PQC crate (recon: `docs/recon/sequoia-pqc-api.md`),
not guessed.

| Python | sequoia call | recon § |
|---|---|---|
| `Cert.from_bytes` | `Cert::from_bytes` (`parse::Parse`) | §1 |
| `Cert.fingerprint` | `cert.fingerprint().to_hex()` | §6 |
| `Cert.has_secret_key` | `cert.is_tsk()` | §1 |
| `Cert.is_post_quantum` | scan `keys().pk_algo()` for ML-DSA/ML-KEM | §7 |
| `Cert.to_armor` | `cert.armored().serialize(buf)` | §5 |
| `Cert.verify_detached` | `DetachedVerifierBuilder::from_bytes` + `VerificationHelper` + `MessageLayer::SignatureGroup` | §4 |
| `Key.generate` | `CertBuilder::{new,set_profile(RFC9580),set_cipher_suite,add_userid,set_primary_key_flags,add_subkey,set_password,generate}` | §2 |
| `Key.cert` | `cert.clone().strip_secret_key_material()` | §5 |
| `Key.is_protected` | `keys().secret()… secret().is_encrypted()` | §3 |
| `Key.to_armor` | `cert.as_tsk().armored().serialize(buf)` | §5 |
| `Key.sign_detached` | key select `keys().secret().with_policy().…for_signing()`, `decrypt_secret`, `into_keypair`, `Message`→`Armorer`→`Signer::detached` | §3 |

**Crypto suites:** `CipherSuite::MLDSA87_Ed448` (L5) / `MLDSA65_Ed25519` (L3) /
`Cv25519` / `RSA4k` / `RSA3k`; `Profile::RFC9580` (v6) vs `RFC4880` (v4).

**Error bridging:** `create_exception!(_sk_pgp, PgpError, PyException)`; a
`to_py_err(impl Display)` maps any error to `PgpError`. The `pyo3/anyhow` feature
also auto-converts `anyhow::Error` (sequoia's `Result` error) on `?`.

**Verification helper:** `OneCertHelper { cert }` implements `VerificationHelper`
— `get_certs` returns the single trusted cert; `check` accepts iff some
`VerificationResult` in a `SignatureGroup` is `Ok` (composite AND-semantics is
already inside that `Ok`).

### Deliberately TODO-stubbed (compile, raise `PgpError`)

- `Key.sign_inline` / `Cert.verify_inline` — inline `Signer` + `LiteralWriter`
  on sign; embedded-data extraction on verify (recon shows detached only).
- `Cert.encrypt` / `Key.decrypt` — `serialize::stream::{Encryptor,Recipient,
  LiteralWriter}` and `parse::stream::{DecryptorBuilder,DecryptionHelper}`
  (recon §7; v1 may defer — sign/verify/cert are the priority).
- `Key.add_pqc_subkeys` — in-process equivalent of `sq key subkey add` (sequoia
  `KeyBuilder`/subkey-binding path, additive, fingerprint-preserving); not pinned
  in recon.
- `Cert.rsa_public_numbers` / `ed25519_public_bytes` — public-MPI extraction for
  DID/JWK (`capauth/did.py`); exact `mpi::PublicKey` access path TBD.

---

## 3. Test plan

**Phase 0 = sk_pgp parity** (recon worklist Phase 0). Acceptance = byte-compatible
verify of existing PGPy/`sq`-produced sigs and vice-versa, for both classical
(Ed25519/RSA) and PQC (mldsa87-ed448, mldsa65-ed25519) suites.

`tests/` (pytest), runnable after `maturin develop`:

1. **Round-trips (real-bound):**
   - `Key.generate(...)` → `.sign_detached(data, pw)` → `key.cert.verify_detached(sig, data)` is `True`.
   - tamper `data` → `verify_detached` is `False` (never raises).
   - `Key.generate(..., password="x")` → `.is_protected` is `True`; sign without
     password → `PgpError`.
   - fingerprint length: 64 for `rfc9580`, 40 for `rfc4880`; UPPER, no spaces.
   - `is_post_quantum` True for mldsa* suites, False for cv25519/rsa*.
   - `to_armor()` → `from_armor()` round-trips; `Cert.has_secret_key` False for
     `key.cert`, True for the secret `Cert`.
2. **Cross-impl golden vectors:** sign with today's `sq`/PGPy, verify with sk_pgp,
   and vice-versa (a vectors dir like `sk_pqc/test_vectors/`). Anchors interop.
3. **Cheap-suite fixture path:** tests opt into `cv25519`/`rsa3k` (PQC keygen is
   slow) — matches the existing RSA-1024/2048 fixtures in skcomms/skchat tests.
4. **TODO stubs:** each raises `PgpError` with the "not implemented yet" marker
   (guards against silent wrong answers before they're built).
5. **Failure modes:** malformed armor → `PgpError`; `Key.from_bytes` on a
   public-only cert → `PgpError`.

CI note: this build links a specific OpenSSL 3.6.2 + liboqs 0.14, so tests run in
that environment (not manylinux). Keep a classical-only smoke subset that needs
no liboqs for fast feedback.

---

## 4. Migration plan (additive, behavior-preserving)

Principle from the recon worklist: sk_pgp lands as a **new optional backend/branch
behind a flag**; PGPy stays until parity is proven per repo. No call site changes
its *contract* — only the implementation behind it. Order:

**Phase 0 — this repo.** Build + green the parity suite (§3) for classical + PQC.

**Phase 1 — capauth (lowest blast radius, highest value).**
1. `src/capauth/crypto/skpgp_backend.py` — new `SkPgpBackend` (§1.4), additive;
   registers beside `pgpy_backend.py` / `sequoia_backend.py`.
2. Route `generate_keypair / sign / verify / fingerprint_from_armor /
   add_pqc_subkeys` through sk_pgp **in-process** (drop the `sq` subprocess). This
   is where sk_pgp first earns its keep: **PQC signing without shelling `sq`.**
3. `capauth/did.py` (106–124): swap RSA-number extraction to
   `Cert.rsa_public_numbers()` / `ed25519_public_bytes()` (needs those stubs done).
4. Keep `PGPyBackend` + `SequoiaBackend` selectable for fallback/comparison.

**Phase 2 — skcomms signing/identity (transport-auth core).**
5. `skcomms/signing.py` `EnvelopeSigner`/`EnvelopeVerifier` detached sign/verify
   → sk_pgp (the `HybridEnvelopeSigner`/`pqsig` path already non-PGPy; converge).
6. `skcomms/grants.py` consent-token sign/verify → sk_pgp.
7. `skcomms/peers.py` + `nostr_discovery.py` `fingerprint_*`
   → `Cert.from_bytes(...).fingerprint`.
8. `skcomms/capauth_validator.py` — load-by-fingerprint + detached verify over str
   payloads, and **retire the `gpg --export` subprocess** in favor of
   `Cert.from_bytes` / an sk_pgp keyring lookup.

**Phase 3 — skcomms + skchat message crypto (needs encrypt/decrypt stubs done).**
9. `skcomms/crypto.py` encrypt/decrypt/sign/verify payload.
10. `skchat/crypto.py` `ChatCrypto` + module helpers.
11. `skchat/files.py` + `skchat/group.py` key wrap/unwrap — **bonus:** sk_pgp's PQC
    `encrypt`/`add_pqc_subkeys` enables the hybrid X25519+ML-KEM-768 target that
    closes the HNDL-exposed classical wraps.
12. Sync/delete the `skchat/.claude/worktrees/pqc-q4/` mirror.

**Phase 4 — tests + cutover.**
13. Point test fixtures (skcomms/tests, skchat/tests `conftest.py`) at sk_pgp's
    cheap-suite `generate(...)`; keep RSA-1024/2048 fixtures runnable.
14. Flip the default backend to sk_pgp per repo once its parity suite is green;
    leave PGPy installable as a fallback for one release, then drop the PGPy and
    `sq`/`gpg` subprocess dependencies.

**Out of scope (no PGPy today):** `skcomms.pqsig` (Ed25519+ML-DSA-65 envelope
sigs), `skcomms.pqkem`/`pqdm` (X25519+ML-KEM-768 sealing), `skcomms.tofu`
(opaque-string fingerprint store). sk_pgp should *converge* with pqsig/pqkem but
does not replace them.
