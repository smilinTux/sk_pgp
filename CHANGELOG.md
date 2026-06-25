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

### Added — TODO stubs (compile, raise `PgpError`)

- `Key.sign_inline` / `Cert.verify_inline`.
- `Cert.encrypt` / `Key.decrypt` (ML-KEM message crypto).
- `Key.add_pqc_subkeys` (additive, fingerprint-preserving).
- `Cert.rsa_public_numbers` / `ed25519_public_bytes` (DID/JWK).

### Notes

- Honesty: **post-quantum / quantum-resistant, never "quantum-proof."** Hybrid
  composite sigs valid iff **both** legs verify. Binds sequoia + liboqs; no
  hand-rolled crypto. FIPS 203/204/205, RFC 8032/9580, draft-ietf-openpgp-pqc.
