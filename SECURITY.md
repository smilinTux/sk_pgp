# Security Policy — sk_pgp

sk_pgp is a **crypto component**: it generates, parses, signs with, and verifies
OpenPGP key material (classical and post-quantum). This file states the threat model,
the secret-handling rules, the dependency posture, and how to report a vulnerability.

> **Honest-claim banner:** these are **post-quantum / quantum-resistant** algorithms,
> **never** "quantum-proof," "quantum-safe," or "unbreakable." Every security claim
> here is **scoped to the signing surface** and cites the FIPS number + hybrid-vs-classical.
> sk_pgp **binds** vetted libraries and **hand-rolls no cryptography**.

---

## Reporting a vulnerability

- **Do not** open a public issue for a security defect.
- Report privately to the maintainers (smilinTux / Chef) via the project's private
  security channel; if you only have a public path, open a minimal issue titled
  "security — please contact" with **no** technical detail and request a private
  channel.
- Include: affected version (`sk_pgp.__version__`), OS/arch, OpenSSL + liboqs
  versions, a minimal reproducer, and the impact you believe it has.
- Expect acknowledgement, a severity assessment, and a remediation plan. Fixes ship
  as a patch release with a dated `CHANGELOG.md` entry; we credit reporters who want
  credit.

**Coordinated disclosure:** because the real cryptographic assurance lives in
**sequoia-openpgp / OpenSSL / liboqs**, a primitive-level finding should also be
reported upstream. sk_pgp will pin/patch and advise consumers.

---

## What sk_pgp is (and is not) — scope of the security claim

| Surface | State | Honest claim |
|---|---|---|
| **Signatures** (detached) | Hybrid composite **ML-DSA-87 + Ed448** (L5) / **ML-DSA-65 + Ed25519** (L3); valid **iff BOTH legs** verify | **Post-quantum / quantum-resistant signing** (FIPS 204 + RFC 8032), additive classical leg retained |
| **KEM / message encryption** | **TODO** — `Cert.encrypt` / `Key.decrypt` are stubs that raise `PgpError` | **No claim.** sk_pgp does **nothing for HNDL** today |
| **Transport / TLS** | N/A — sk_pgp is a library, no channel | No "end-to-end" claim originates here |
| **Symmetric / hashing** | AES-256-GCM, SHA-256/384 via sequoia | Quantum-acceptable (Grover-only); **AES-256 is not "quantum-broken"** |

**Therefore:** describe sk_pgp as a **post-quantum signing engine**. Do **not** call
this repo "PQC encryption," "HNDL-resistant," or "end-to-end quantum-resistant" —
only signatures are migrated, and signatures are not retroactively breakable, which
is precisely why HNDL is addressed by KEM (a separate, still-TODO surface).

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
- **HNDL / confidentiality.** sk_pgp signs; it does not yet wrap or encrypt. The
  hybrid `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` KEM is **TODO**; until then HNDL is
  not addressed by this repo.
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

## CRYPTOGRAPHY_STANDARD.md compliance statement

sk_pgp conforms to the SK **CRYPTOGRAPHY_STANDARD** honest-claim and binding rules:

- Uses **"post-quantum" / "quantum-resistant,"** never the forbidden words
  ("quantum-proof," "quantum-safe," "unbreakable," "CNSA 2.0 compliant," "FIPS 206/
  Falcon"); never implies AES-256 is quantum-broken.
- **Every claim is scoped to the signing surface** and cites FIPS 204 (ML-DSA) /
  FIPS 203 (ML-KEM, future) / RFC 8032 (EdDSA) / RFC 9580 (v6) /
  draft-ietf-openpgp-pqc-17 (composite) + NIST CSWP 39 (agility).
- **Binds** vetted libraries (sequoia → crypto-openssl/OpenSSL 3.6.2 → liboqs 0.14);
  **hand-rolls no crypto.**
- Composite signatures are **hybrid (lattice AND classical)** with the classical leg
  **additive/reversible**; the **future** KEM uses the standard combiner
  `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` — **never XOR, never pure-PQ**.
- **Maturity tier declared honestly: T3-capable (signing); T2 (hybrid KEM) is TODO**
  — see [SOP.md §9](SOP.md). HNDL is **not** claimed.
- **Self-report evidence:** per-object `is_post_quantum` + fingerprint version-length
  + the passing PQC keygen test back every "this is post-quantum" statement.

License: **Apache-2.0** ([LICENSE](LICENSE)).
