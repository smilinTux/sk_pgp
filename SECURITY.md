# Security Policy — sk_pgp

sk_pgp is a **crypto component**: it generates, parses, signs with, and verifies
OpenPGP key material (classical and post-quantum). This file states the threat model,
the secret-handling rules, the dependency posture, and how to report a vulnerability.

> **Honest-claim banner:** these are **post-quantum / quantum-resistant** algorithms,
> **never** "quantum-proof," "quantum-safe," or "unbreakable." Every security claim
> here is **scoped to the signing surface** and cites the FIPS number + hybrid-vs-classical.
> sk_pgp **binds** vetted libraries and **hand-rolls no cryptography**.

> ⚠️ **Experimental, pre-1.0, NOT independently security-audited.** No third-party
> security audit, fuzzing, or formal review has been performed on sk_pgp. The
> primitives come from vetted upstreams (sequoia-openpgp, OpenSSL 3.6, liboqs); the
> original code is the PyO3 binding surface and the Python ergonomics layer. A passing
> test suite proves interop and behavior, **not** the absence of side-channels,
> memory-safety defects at the FFI boundary, or protocol flaws. **Review it yourself
> before production use, and do not trust it beyond the evidence.**

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | current |
| < 0.1.0 | not supported (pre-release) |

Until 1.0, only the latest published `0.x` line receives security fixes. sk_pgp is not
yet published to PyPI, so "published" currently means the newest tag on `main`.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

**Primary channel:** GitHub **private vulnerability reporting**. Use "Report a
vulnerability" on the Security tab of
[`smilinTux/sk_pgp`](https://github.com/smilinTux/sk_pgp/security/advisories/new).
This creates a private advisory only the maintainers can see.

**Fallback:** if private reporting is unavailable to you, open a minimal public issue
titled "security, please contact" with **no** technical detail, and request a private
channel.

Please include: affected version (`sk_pgp.__version__`), OS and architecture, OpenSSL
and liboqs versions, a minimal reproducer, and the impact you believe it has.

**Acknowledgement SLA: within 72 hours.** After acknowledgement you can expect a
severity assessment, a remediation plan, and a target fix or mitigation within 90
days, with the disclosure date coordinated with you. Fixes ship as a patch release
with a dated `CHANGELOG.md` entry. Reporters are credited unless they ask otherwise.

**Coordinated disclosure:** the real cryptographic assurance lives in
**sequoia-openpgp / OpenSSL / liboqs**, so a primitive-level finding should also be
reported upstream. sk_pgp will pin or patch and advise consumers.

### Safe harbour

We will not pursue or support legal action against anyone who, in good faith, finds
and reports a vulnerability under this policy: research only against your **own**
keys, data and installations; no access to or exfiltration of other people's data; no
denial of service, spam, or social engineering of maintainers or users; and no public
disclosure before a coordinated date. Good-faith research conducted this way is
authorised, and we will work with you rather than against you. If you are unsure
whether an action is in scope, ask first via the private channel.

### What we especially want to hear about

- A composite signature reported valid when only **one** leg verifies.
- `verify_detached` or `verify_inline` returning data or `True` for input that did not
  verify, or `verify_inline` leaking unverified bytes instead of `(False, b"")`.
- A path where malformed input crashes the extension instead of raising `PgpError`.
- Passphrase or secret-key material reaching a log, an exception message, or a core dump.
- Any place a claim in these docs overstates assurance, including the tier statement.

---

## What sk_pgp is (and is not) — scope of the security claim

| Surface | State | Honest claim |
|---|---|---|
| **Signatures** (detached) | Hybrid composite **ML-DSA-87 + Ed448** (L5) / **ML-DSA-65 + Ed25519** (L3); valid **iff BOTH legs** verify | **Post-quantum / quantum-resistant signing** (FIPS 204 + RFC 8032), additive classical leg retained |
| **KEM / message encryption** | Real-bound. `Cert.encrypt` / `Key.decrypt` do OpenPGP message encryption. To a **PQC** cert the recipient subkey is the **ML-KEM-1024 + X448** (or ML-KEM-768 + X25519) composite; to a **classical** cert it is plain ECDH. | **Post-quantum message encryption, only when the recipient certificate is PQC** (FIPS 203). Confidential if **either** leg holds. **No** HNDL claim for messages encrypted to a classical cert. |
| **Transport / TLS** | N/A — sk_pgp is a library, no channel | No "end-to-end" claim originates here |
| **Symmetric / hashing** | AES-256-GCM, SHA-256/384 via sequoia | Quantum-acceptable (Grover-only); **AES-256 is not "quantum-broken"** |

**Therefore:** describe sk_pgp as a **post-quantum OpenPGP engine** that both signs
and encrypts. Two limits keep that claim honest:

1. **The encryption claim is conditional on the recipient certificate.** A message
   encrypted to a `cv25519` or `rsa*` cert is protected by **classical** ECDH/RSA and
   is fully exposed to Harvest-Now-Decrypt-Later. Only a PQC cert (one carrying an
   ML-KEM composite subkey, which `is_post_quantum` reports) earns the post-quantum
   confidentiality claim.
2. **sk_pgp is not an end-to-end system.** It has no transport, no session, no key
   distribution and no trust decisions. Do not call this repo "end-to-end
   quantum-resistant"; that property belongs to a protocol, not to a library.

Do **not** use the forbidden words ("quantum-proof", "quantum-safe", "unbreakable",
"CNSA 2.0 compliant") about anything in this repo.

---

## Threat model

### In scope (what sk_pgp must get right)
1. **Signature forgery / partial-composite acceptance.** A composite signature MUST
   be accepted **only if both** the ML-DSA leg **and** the EdDSA leg verify. sk_pgp
   relies on sequoia's composite AND-semantics and exposes it via `verify_detached`
   returning a single `bool`. Mitigation: never report a partial composite as valid;
   covered by `test_pqc_v6_keygen` + tamper checks.
2. **Verify that raises vs. returns.** `verify_detached` MUST return `False` on a bad
   signature (callers `return False`), and raise `PgpError` **only** on malformed
   signature *bytes*. A verify path that throws on attacker-controlled input is a DoS
   and a logic hazard. Covered by `test_classical_sign_verify_roundtrip`.
3. **Passphrase / secret-key exposure.** Protected keys must stay encrypted until an
   explicit `password` unlocks them in-process; passphrases must never be logged or
   embedded in docs. `Key.is_protected` is the gate.
4. **FFI safety.** No panic may cross the PyO3 boundary; every sequoia/anyhow error
   maps to a catchable `PgpError` (`to_py_err` + `pyo3/anyhow`). A panic across FFI
   is undefined behavior.
5. **Algorithm-pin integrity.** The build MUST resolve `sequoia-openpgp =2.2.0-pqc.1`
   with the `crypto-openssl` backend. A silent downgrade to a non-PQC sequoia/backend
   would make "post-quantum" claims false. The `=` pin + `default-features = false`
   guard this; CI must fail if the lock drifts.
6. **Wheel / SONAME integrity.** The self-contained wheel bundles brew OpenSSL 3.6.2
   under a **private SONAME**. A wheel that instead binds the ambient system
   `libcrypto.so.3` may silently lose the PQC symbols (and break in mixed processes).
   The build-time mixed-OpenSSL import test is the gate (SOP §3.2).

### Out of scope (handled elsewhere / not yet built)
- **Confidentiality for anything encrypted to a classical certificate.** sk_pgp does
  encrypt (see the scope table above), but only a **PQC** recipient certificate gets
  the post-quantum property. Messages encrypted to `cv25519` or `rsa*` certs remain
  exposed to Harvest-Now-Decrypt-Later, and that is the caller's choice of recipient
  key, not something this library can fix.
- **The sk-standards `HKDF-SHA256(X25519_ss || MLKEM768_ss)` combiner.** Not
  implemented here and not planned here; that construction lives in the `sk-pqc`
  family. sk_pgp uses the OpenPGP composite KEM instead.
- **Key storage / rotation / transport.** Owned by `capauth` / `skcomms` / the
  CapAuth bunker, not by this library.
- **Supply-chain of the bound crypto.** The cryptographic assurance is sequoia +
  OpenSSL + liboqs; sk_pgp inherits their posture and pins their versions.
- **Side-channel resistance of the primitives.** Provided (or not) by OpenSSL/liboqs;
  sk_pgp adds no constant-time guarantees of its own.

---

## Secret-handling rules

- **Never inline a live private key or passphrase** in code, docs, tests, or commit
  messages. Test keys are generated on the fly (`Key.generate`) or are dedicated,
  non-production fixtures.
- Passphrases are **per-call arguments** (`password=...`), never environment-baked
  defaults and never logged.
- `Key.to_armor()` emits **TSK** (secret) armor — treat its output as a secret; do
  not write it to logs or shared paths.
- `Key.cert` strips secret material; publish/transmit **`.cert` / `.to_armor()` of
  the cert**, never the `Key`.

---

## Dependency / build posture

| Dependency | Pin | Why it matters |
|---|---|---|
| `sequoia-openpgp` | **`=2.2.0-pqc.1`** (`crypto-openssl`, `compression`; `default-features=false`) | the OpenPGP v6 + composite-PQC engine; the `=` pin prevents resolving to a **non-PQC** release |
| OpenSSL | linuxbrew **3.6.2** (bundled under a private SONAME in the wheel) | the **only** Sequoia backend with ML-DSA/ML-KEM; system OpenSSL lacks the symbols |
| liboqs | **0.14** | ML-DSA-65/87 + ML-KEM-768/1024 primitives |
| pyo3 | 0.24 (`abi3-py39`, `anyhow`) | stable-ABI wheel; safe error bridging across FFI |

- **No hand-rolled crypto.** sk_pgp contains zero original cryptographic code; it is a
  Python ergonomics layer over bound libraries.
- **Reproducibility:** `Cargo.lock` is committed; a lockfile drift that changes the
  sequoia/openssl/liboqs versions is a release-blocking event.
- **Wheel scope:** the published wheel embeds a specific OpenSSL 3.6.2 / liboqs 0.14
  and is **not** manylinux-portable yet — disclosed, not hidden.

---

## CRYPTOGRAPHY_STANDARD compliance statement

Standard: [sk-standards `standards/CRYPTOGRAPHY_STANDARD.md`](https://github.com/smilinTux/sk-standards/blob/main/standards/CRYPTOGRAPHY_STANDARD.md).

sk_pgp conforms to the SK **CRYPTOGRAPHY_STANDARD** honest-claim and binding rules:

- Uses **"post-quantum" / "quantum-resistant"**, never the forbidden marketing words;
  never implies AES-256 is quantum-broken (it is symmetric, and Grover only halves the
  effective strength).
- **Every claim is scoped to a named surface** (signing, or OpenPGP message
  encryption) and cites FIPS 204 (ML-DSA) / FIPS 203 (ML-KEM) / RFC 8032 (EdDSA) /
  RFC 9580 (v6) / draft-ietf-openpgp-pqc-17 (composite) + NIST CSWP 39 (agility).
- **Binds** vetted libraries (sequoia → crypto-openssl / OpenSSL 3.6.2 → liboqs 0.14);
  **hand-rolls no crypto.**
- Composite signatures are **hybrid (lattice AND classical)** with the classical leg
  **additive and reversible**, never XOR, never pure-PQ.
- **Combiner disclosure:** the KEM path is the **OpenPGP composite KEM**, **not** the
  sk-standards `HKDF-SHA256(X25519_ss || MLKEM768_ss)` combiner used by the `sk-pqc`
  family. Both are hybrid; they are **different constructions and not wire-compatible**.
  sk_pgp does not implement that combiner and does not claim to.
- **Maturity tier declared honestly: T2 + T3**, with T1 **partial** (no runnable
  self-report). See [SOP.md section 9](SOP.md) for per-axis evidence.
- **Self-report evidence:** sk_pgp has **no self-report command**. Per-object
  `is_post_quantum`, the fingerprint version-length, and the passing PQC tests back
  every "this is post-quantum" statement.

> **Correction, 2026-08-15.** This section previously declared "T3-capable (signing);
> T2 (hybrid KEM) is TODO" and described the KEM as future work using the sk-standards
> combiner. Both statements were stale and are corrected above: the KEM surface has
> been real-bound since commit `33a4c6c`, and it uses the OpenPGP composite
> construction rather than the sk-standards combiner.

License: **Apache-2.0** ([LICENSE](LICENSE)).
