# Changelog

All notable changes to **sk_pgp** are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [0.1.0] — Unreleased

Initial buildable skeleton: PyO3 bindings to PQC `sequoia-openpgp =2.2.0-pqc.1`
(crypto-openssl) + maturin packaging. The PGPy replacement scaffold.

### Added — real-bound

- `Cert`: `from_bytes` / `from_armor` / `from_file`; `fingerprint`,
  `is_post_quantum`, `has_secret_key` properties; `to_armor` / `to_bytes`;
  `verify_detached(sig, data)` (composite AND-semantics; returns bool, never
  raises on a bad signature).
- `Key`: `from_bytes` / `from_file`; `generate(userid, suite, password, profile)`
  for PQC (`mldsa87-ed448` L5 / `mldsa65-ed25519` L3) and classical
  (`cv25519` / `rsa4k` / `rsa3k`) suites under RFC 9580 (v6) or RFC 4880 (v4);
  `cert`, `fingerprint`, `is_post_quantum`, `is_protected` properties; `to_armor`;
  `sign_detached(data, password=None)` (unlocks protected keys).
- Module: `PgpError` exception; `CIPHER_MLDSA87_ED448` / `CIPHER_MLDSA65_ED25519`
  / `CIPHER_CV25519` constants; `__version__`.

### Added — real-bound (inline sign/verify + ML-KEM message crypto)

- `Key.sign_inline(data, password=None)` — armored **inline** (attached-signature)
  OpenPGP message (`Message → Armorer → Signer → LiteralWriter`); composite
  ML-DSA+EdDSA signing transparent for the PQC suites.
- `Cert.verify_inline(signed) -> (bool, bytes)` — verifies an inline message and
  returns the embedded data. Non-raising on a bad signature (returns
  `(False, b"")` and **withholds** the unverified bytes); raises `PgpError` only
  on unparseable input. Composite AND-semantics (both legs must verify).
- `Cert.encrypt(plaintext, cipher="AES256") -> bytes` — armored OpenPGP MESSAGE to
  the cert's encryption subkey; for `mldsa*` suites this is the **ML-KEM (FIPS 203)**
  composite KEM (ML-KEM-1024+X448 / ML-KEM-768+X25519). `cipher` selects the body
  cipher (AES128/192/256).
- `Key.decrypt(ciphertext, password=None) -> bytes` — ML-KEM/ECDH decrypt via a
  single-TSK `DecryptionHelper`; wrong-key / locked-key reject as `PgpError`.

### Added — TODO stubs (compile, raise `PgpError`)

- `Key.add_pqc_subkeys` (additive, fingerprint-preserving).
- `Cert.rsa_public_numbers` / `ed25519_public_bytes` (DID/JWK).

### Notes

- Honesty: **post-quantum / quantum-resistant, never "quantum-proof."** Hybrid
  composite sigs valid iff **both** legs verify. Binds sequoia + liboqs; no
  hand-rolled crypto. FIPS 203/204/205, RFC 8032/9580, draft-ietf-openpgp-pqc.

### Added — docs / packaging (sk-standards parity)

- README brought to **hub** form: badge row, an **Experimental · pre-1.0 · NOT
  independently security-audited** banner, and explicit `sk-pqc-{py,rs,dart}` /
  capauth / skcomms / skchat / sk-standards cross-links.
- `docs/ARCHITECTURE.md` — the data-flow view (layering + keygen + detached
  sign→verify sequence diagrams + trust-boundary table), per DATA_FLOW_STANDARD.
- `examples/` — runnable, self-checking `pqc_v6_sign_verify.py` (ML-DSA-87 + Ed448
  v6 keygen → sign → verify, with composite AND-semantics + tamper check) and a fast
  `classical_quickstart.py`, plus `examples/README.md`.
- `pyproject.toml`: PyPI metadata polish — `readme`, expanded keywords + classifiers
  (`Development Status :: 3 - Alpha`, email/crypto topics), Documentation/Changelog/
  Issues URLs, and a registered `slow` pytest marker. (Still **not** published to PyPI.)
