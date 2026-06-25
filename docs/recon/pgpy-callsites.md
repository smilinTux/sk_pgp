# sk_pgp Recon — PGPy / gpg Call-Site Audit

**Scope:** READ-ONLY enumeration of every place `sk_pgp` must eventually replace
PGPy (and the `sq`/`gpg` subprocess shims) in the Python signing/identity paths
across `skcomms`, `skchat`, and `capauth`.

**Goal of sk_pgp:** a sovereign Python OpenPGP library (PyO3 → PQC-capable
sequoia-openpgp 2.2.0-pqc.1 + maturin) that is a **drop-in for PGPy** for the
operations below, and additionally hosts v6/RFC9580 + PQC (ML-DSA / ML-KEM)
keys that PGPy and gpg 2.4 cannot. Hybrid composite sigs are valid iff BOTH legs
verify; we bind sequoia/liboqs and never hand-roll crypto (FIPS 203/204/205,
RFC 8032/9580, draft-ietf-openpgp-pqc).

The PGPy surface in use is small and repetitive. Across all three repos the
*entire* dependency on PGPy reduces to **8 distinct operations**:

1. Parse a key/cert from armor → `PGPKey.from_blob` / `from_file`
2. Read a fingerprint → `key.fingerprint`
3. Detached/inline **sign** → `key.unlock(pp)` + `key.sign(PGPMessage.new(...))`
4. **Verify** a signature → `PGPKey.from_blob` + `PGPSignature.from_blob` + `pub.verify(...)`
5. **Encrypt** to a public key → `pub.encrypt(PGPMessage.new(...))`
6. **Decrypt** with a private key → `key.unlock(pp)` + `key.decrypt(PGPMessage.from_blob(...))`
7. **Generate** a keypair → `PGPKey.new(...)` + `add_uid` + `add_subkey` + `protect`
8. Parse a bare detached signature → `PGPSignature.from_blob` (structural check)

`capauth` additionally has the `sq`-subprocess **SequoiaBackend** (PQC), which
is the *reference behavior* sk_pgp must provide **in-process** instead of
shelling out. `gpg` appears only as a fallback keyring lookup in one file.

---

## 1. Production call sites (non-test)

### capauth — `src/capauth/crypto/pgpy_backend.py`  (PGPy `CryptoBackend`, the default)
This file *is* the canonical operation set; sk_pgp's API should mirror its
`CryptoBackend` ABC (`generate_keypair / sign / verify / fingerprint_from_armor`).

| line | op | call | inputs → outputs |
|------|----|------|------------------|
| 9–17 | import | `import pgpy` + constants | module-level hard import |
| 74 | generate (sign primary) | `PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)` | → primary `PGPKey` |
| 76 | generate (RSA primary) | `PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)` | → primary `PGPKey` |
| 78–85 | uid + flags | `PGPUID.new(name,email)` → `key.add_uid(uid, usage={Sign,Certify}, hashes=…, ciphers=…, compression=…)` | binds UID with usage flags |
| 88 | generate (enc subkey) | `PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)` | → encryption subkey |
| 90 | generate (RSA subkey) | `PGPKey.new(RSAEncryptOrSign, 4096)` | → encryption subkey |
| 92–95 | add subkey | `key.add_subkey(sub, usage={EncryptCommunications,EncryptStorage})` | attaches enc subkey |
| 97 | protect | `key.protect(passphrase, AES256, SHA256)` | passphrase-locks secret material |
| 99–101 | export | `key.fingerprint`, `str(key.pubkey)`, `str(key)` | → fingerprint, pub armor, priv armor |
| 135 | parse priv | `PGPKey.from_blob(private_key_armor)` | armor → `(PGPKey, _)` |
| 137 | unlock | `key.unlock(passphrase)` (context manager) | decrypts secret in scope |
| 138 | wrap msg | `PGPMessage.new(data, cleartext=False)` | bytes → `PGPMessage` |
| 139–140 | **sign** (inline) | `key.sign(message)` then `message |= sig` | → signed `PGPMessage`; returns `str(message)` (data+sig, for round-trip) |
| 166 | parse pub | `PGPKey.from_blob(public_key_armor)` | armor → pubkey |
| 167 | parse signed msg | `PGPMessage.from_blob(signature_armor)` | armor → `PGPMessage` |
| 173–177 | embedded-data check | `signed_msg.message` compared to `data` | substitution-attack guard |
| 179 | **verify** | `pub_key.verify(signed_msg)` → truthy `SignatureVerification` | → bool |
| 197–198 | **fingerprint** | `PGPKey.from_blob(key_armor)` → `str(key.fingerprint)` | 40(v4)/64(v6) hex |

### capauth — `src/capauth/crypto/sequoia_backend.py`  (PQC reference, `sq` subprocess)
sk_pgp must replicate these in-process. Each `_run([...])` shells `sq`.

| line | op | behavior sk_pgp must provide in-process |
|------|----|------------------------------------------|
| 132–183 | **generate (PQC)** | `sq key generate --own-key --name --email --cipher-suite <mldsa87-ed448|mldsa65-ed25519|cv25519|rsa4k> --profile rfc9580` → private armor; then `sq key delete` to derive **cert (public)** armor; `sq inspect` to read fingerprint. Returns `KeyBundle(fingerprint, public_armor, private_armor, algorithm)`. |
| 185–233 | **sign (protected, detached PQC)** | `sq sign --signer-file <key> --signature-file <out> <data>` with global `--password-file`+`--batch` to unlock a protected key non-interactively. Returns **armored detached signature**. |
| 235–257 | **verify (detached)** | `sq verify --signer-file <cert> --signature-file <sig> <data>` → True / False (no exception leaks). |
| 259–264 | **fingerprint_from_armor** | `sq inspect <key>` → `Fingerprint:` regex (40–64 hex). |
| 270–385 | **add_pqc_subkeys (additive)** | two `sq key subkey add` calls: ML-DSA-87+Ed448 `--can-sign` then ML-KEM-1024+X448 `--can-encrypt universal`, same `--cipher-suite`; requires v6/RFC9580; asserts primary fingerprint **unchanged** (additive invariant). |
| 391–435 | **inspect helpers** | `sq inspect` → primary algo / all subkey algos / map to capauth `Algorithm`. |

### capauth — `src/capauth/did.py`
| line | op | call | notes |
|------|----|------|-------|
| 106–124 | parse pub + **RSA numbers** | `PGPKey.from_blob(armor)` then `key.pubkey.public_key.public_numbers()` (0.6+) / `key.pubkey._key.keymaterial.n/e` (0.5.x) | needs `(n,e)` ints for JWK. **sk_pgp must expose RSA public params** (n,e) — and ideally Ed25519/curve params — for DID JWK emission. |

### skcomms — `src/skcomms/signing.py`  (Envelope v1 signer/verifier — core transport auth)
| line | op | call | inputs → outputs |
|------|----|------|------------------|
| 86–90 | parse priv + fp | `PGPKey.from_blob(private_key_armor)`; `str(key.fingerprint)` | EnvelopeSigner ctor; caches key + fp |
| 99–109 | **detached sign** | `PGPMessage.new(canonical, cleartext=False)`; `key.unlock(pp)` if protected; `key.sign(msg)` → `str(sig)` | canonical bytes → armored **detached** sig |
| 263–266 | parse pub + fp | `PGPKey.from_blob(public_key_armor)`; `str(key.fingerprint)` | verifier keyring registration |
| 324–331 | **verify (detached)** | `PGPKey.from_blob(pub_armor)`; `PGPSignature.from_blob(signature)`; `PGPMessage.new(canonical)`; `msg |= sig`; `pub_key.verify(msg)` | → bool |

> Note: `HybridEnvelopeSigner` / `_verify_hybrid` (lines 155–393) already use the
> sovereign `skcomms.pqsig` (Ed25519+ML-DSA-65) and do **not** touch PGPy — they
> are the existing PQC envelope path and are out of scope for replacement (but are
> the pattern sk_pgp's hybrid signing should converge with).

### skcomms — `src/skcomms/crypto.py`  (legacy MessageEnvelope payload crypto)
| line | op | call |
|------|----|------|
| 172–183 | **encrypt** | `PGPKey.from_blob(recipient_public_armor)`; `PGPMessage.new(content)`; `recipient_key.encrypt(msg, cipher=AES256)` → `str(encrypted)` |
| 233–244 | **decrypt** | `PGPKey.from_blob(self._private_armor)`; `PGPMessage.from_blob(content)`; `key.unlock(pp)`; `key.decrypt(msg)` → `.message` |
| 282–296 | **sign payload** (detached) | `PGPKey.from_blob`; `PGPMessage.new(content, cleartext=False)`; `key.unlock`; `key.sign(msg)` → `str(sig)` |
| 325–334 | **verify payload** | `PGPKey.from_blob(sender_public_armor)`; `PGPSignature.from_blob(sig)`; `PGPMessage.new(content)`; `msg |= sig`; `pub.verify(msg)` → bool |
| 654 | availability probe | `import pgpy` guarded `_pgp_available` flag |

### skcomms — `src/skcomms/grants.py`  (consent-token signing)
| line | op | call |
|------|----|------|
| 266–279 | **detached sign** | reuses `EnvelopeSigner._key`: `PGPMessage.new(canonical, cleartext=False)`; `key.unlock(pp)` if protected; `key.sign(msg)` → `str(sig)` |
| 319–333 | **verify** + fp | `PGPKey.from_blob(armor)`; `PGPSignature.from_blob(tok.signature)`; `PGPMessage.new(canonical)`; `msg |= sig`; `pub.verify(msg)`; then `str(pub_key.fingerprint)` for TOFU |

### skcomms — `src/skcomms/peers.py`
| line | op | call |
|------|----|------|
| 111–117 | **fingerprint_from_pubkey** | `PGPKey.from_blob(armor)` → `str(key.fingerprint).replace(" ","").upper()`; raises `ValueError` on bad armor |

### skcomms — `src/skcomms/nostr_discovery.py`
| line | op | call |
|------|----|------|
| 217–223 | **fingerprint (best-effort)** | `PGPKey.from_blob(pubkey_armor)` → `str(key.fingerprint)`; returns None on failure |

### skcomms — `src/skcomms/capauth_validator.py`  (WebRTC signaling auth)
| line | op | call |
|------|----|------|
| 63–80 | parse + fp scan | `PGPKey.from_file(path)` over globbed `*.asc`; `str(key.fingerprint)` to match a wanted fp |
| 239–251 | **verify detached** (raw) | `PGPSignature.from_blob(sig_bytes)` (from base64url); `pub_key.verify(signed_text, sig)` where `signed_text="capauth:<FP>:<TS>"` — **verify over a Python str + a separate PGPSignature** (not an inline PGPMessage) |
| 289–308 | parse pub | `PGPKey.from_file(path)` / `PGPKey.from_blob(armor)` → `PGPKey` |
| 319–331 | **gpg fallback** | `subprocess.run(["gpg","--export","--armor",fp])` then `PGPKey.from_blob(stdout)` — the **only `gpg` subprocess** in scope; sk_pgp can supersede with its own keyring/lookup but parity = "load pub by fingerprint" |
| 374–389 | **verify detached** | `PGPSignature.from_blob(sig)` (armor or base64url); `pub_key.verify(signed_payload, pgp_sig)` over a str payload |

### skchat — `src/skchat/crypto.py`  (`ChatCrypto` — DM encrypt/sign)
| line | op | call |
|------|----|------|
| 19–21 | import | module-level `import pgpy` + constants (hard dep) |
| 133–135 | parse priv + fp | `PGPKey.from_blob(private_key_armor)`; `str(key.fingerprint)` |
| 173–185 | **encrypt + sign** | `PGPKey.from_blob(recipient_public_armor)`; `PGPMessage.new(content)`; `recipient_key.encrypt(msg, cipher=AES256)`; `self._private_key.unlock(pp)`; `key.sign(msg)` |
| 216–219 | **decrypt** | `PGPMessage.from_blob(content)`; `key.unlock(pp)`; `key.decrypt(msg)` → `.message` |
| 501–506 | **sign** (detached) | `PGPMessage.new(content, cleartext=False)`; `key.unlock(pp)`; `key.sign(msg)` → `str(sig)` |
| 530–540 | **verify** | `PGPKey.from_blob(sender_public_armor)`; `PGPSignature.from_blob(message.signature)`; `PGPMessage.new(content)`; `msg |= sig`; `pub.verify(msg)` → bool |
| 557–558 | **fingerprint** | `PGPKey.from_blob(key_armor)` → `str(key.fingerprint)` |
| 611–612 | structural sig check | `PGPSignature.from_blob(message.signature)` (parse-only validity) |
| 637–639 | **encrypt body** (module fn) | `PGPKey.from_blob(recipient_fingerprint)`; `PGPMessage.new(content)`; `recipient_key.encrypt(msg)` |
| 671–672 | parse priv + decrypt | `PGPKey.from_blob(private_key_armor)`; `PGPMessage.from_blob(encrypted)` |

### skchat — `src/skchat/files.py`  (file-transfer key wrap)
| line | op | call |
|------|----|------|
| 271–276 | **encrypt** transfer key | `PGPKey.from_blob(recipient_public_armor)`; `PGPMessage.new(key_hex)`; `pub.encrypt(msg)` → `str(encrypted)` |
| 438–441 | **decrypt** transfer key | `PGPKey.from_blob(self._private_key_armor)`; `PGPMessage.from_blob(encrypted_key)` (then unlock+decrypt) |

### skchat — `src/skchat/group.py`  (`GroupKeyDistributor`)
| line | op | call |
|------|----|------|
| 1090–1096 | **encrypt** group key | `PGPKey.from_blob(member_public_armor)`; `PGPMessage.new(group_key_hex)`; `pub_key.encrypt(message)` → `str(encrypted)` |
| 1118–1124 | **decrypt** group key | `PGPKey.from_blob(private_key_armor)`; `PGPMessage.from_blob(encrypted_key)`; `key.unlock(pp)`; `key.decrypt(msg)` → `.message` |

> Note: the duplicated tree `skchat/.claude/worktrees/pqc-q4/src/skchat/{crypto,files,group}.py`
> is a worktree mirror of the same code (same ops, shifted line numbers) — fix the
> canonical `src/skchat/` and the worktree converges. Not separately listed.

---

## 2. Test-only call sites (fixtures — migrate last, do not block prod)

These only **generate throwaway RSA-1024/2048 keys** as fixtures and read
`str(key.fingerprint)` / `str(k.pubkey)`; they exercise the prod API, they don't
define new requirements.

- **skcomms/tests:** `test_registry_cli.py`, `test_envelope_v1.py`, `test_peers.py`,
  `test_grants.py`, `test_api_federation_inbox.py`, `test_access_server.py`,
  `test_nostr_discovery.py`, `test_core_send_federated.py`, `test_access_routing.py`,
  `test_federation.py`, `test_mailbox.py`, `test_federation_integration.py`,
  `test_api_access_token.py`, `test_capauth_key_reconcile.py`, `test_pairing.py`,
  `test_access_rbac.py`, `test_store_forward.py`
  — all use `pgpy.PGPKey.new(RSAEncryptOrSign, 1024/2048)` + `from_blob` + `.fingerprint`.
- **skchat/tests:** `conftest.py`, `test_files.py`, `test_group.py`
  (`PGPKey.new(RSAEncryptOrSign, 2048)` + subkey); `test_crypto.py` import guard.
- `skcomms/tests/test_tofu.py`, `test_pairing*.py` use **opaque** fingerprint
  strings (no PGPy) — no migration needed.

Key fixture requirement for sk_pgp: a fast keygen path usable in tests
(classical Ed25519/RSA is fine; PQC keygen is slower — tests should be able to
opt into a cheap suite).

---

## 3. Minimal Python API surface sk_pgp must expose (drop-in target)

Modeled on the *actual* usage above. PGPy's quirks to absorb: `from_blob`
returns `(key, _)` (a tuple); `key.fingerprint` is a spaced string callers
normalize with `.replace(" ","").upper()`; `verify()` returns a truthy object;
sign/decrypt require an `unlock(passphrase)` context; inline-signed messages
carry the data (`signed_msg.message`).

### 3.1 Cert / Key (parse + introspect)
```python
class Cert:                     # public certificate (transferable pubkey)
    @classmethod
    def from_bytes(data: bytes | str) -> "Cert"      # ⇄ PGPKey.from_blob(pub)
    @classmethod
    def from_file(path: str) -> "Cert"               # ⇄ PGPKey.from_file
    @property
    def fingerprint(self) -> str                     # 40 (v4) / 64 (v6) hex, UPPER, no spaces
    @property
    def is_post_quantum(self) -> bool                # has an ML-DSA/ML-KEM component
    # DID/JWK support (capauth/did.py):
    def rsa_public_numbers(self) -> tuple[int,int] | None   # (n, e)
    def ed25519_public_bytes(self) -> bytes | None
    def to_armor(self) -> str

class Key:                      # secret key material (signer/decrypter)
    @classmethod
    def from_bytes(data: bytes | str) -> "Key"       # ⇄ PGPKey.from_blob(priv)
    @classmethod
    def from_file(path: str) -> "Key"
    @property
    def cert(self) -> Cert                            # public half  (⇄ key.pubkey)
    @property
    def fingerprint(self) -> str
    @property
    def is_protected(self) -> bool                    # ⇄ key.is_protected
    def to_armor(self) -> str                         # ⇄ str(key)
```

### 3.2 Sign / Verify
```python
# Detached signature over raw bytes (the dominant skcomms/capauth path).
key.sign_detached(data: bytes, password: str | None = None) -> bytes   # armored detached sig
cert.verify_detached(sig: bytes, data: bytes) -> bool                  # truthy → bool

# Inline-signed message (PGPy round-trip path used by capauth pgpy_backend.sign
# and skchat encrypt-then-sign). Carries the data so verify can re-check it.
key.sign_inline(data: bytes, password: str | None = None) -> bytes     # data + sig
cert.verify_inline(signed: bytes) -> tuple[bool, bytes]                # (valid, embedded_data)
```
Both legs of a hybrid composite (ML-DSA + EdDSA) MUST verify for `verify_*` to
return True — never report a partial composite as valid.

### 3.3 Encrypt / Decrypt
```python
cert.encrypt(plaintext: bytes, cipher: str = "AES256") -> bytes        # ⇄ pub.encrypt(PGPMessage.new(...))
key.decrypt(ciphertext: bytes, password: str | None = None) -> bytes   # ⇄ key.unlock+key.decrypt → .message
```
Inputs/outputs are armored OpenPGP messages (callers `str(...)` them today).

### 3.4 Generate
```python
def generate(
    userid: str,              # "Name <email>"  (or name=, email= kwargs)
    suite: str = "mldsa87-ed448",   # mldsa87-ed448 | mldsa65-ed25519 | cv25519 | rsa4k | ed25519
    password: str | None = None,
    profile: str = "rfc9580", # v6 for PQC; v4/"rfc4880" for classical-compat fixtures
) -> Key                      # Key.cert gives the public half
# Returns a key whose .fingerprint, .to_armor() (priv), .cert.to_armor() (pub)
# reproduce SequoiaBackend.generate_keypair's KeyBundle.

def add_pqc_subkeys(
    key: Key, password: str | None,
    cipher_suite: str = "mldsa87-ed448",
) -> Key                      # additive: ML-DSA-87+Ed448 sign + ML-KEM-1024+X448 enc;
                              # MUST preserve the primary fingerprint (additive invariant).
```

### 3.5 Backend adapter (capauth contract)
sk_pgp should ship a `CryptoBackend`-shaped facade so capauth can register it
beside `PGPyBackend` / `SequoiaBackend` with **zero call-site changes**:
```python
class SkPgpBackend(CryptoBackend):
    def available(self) -> bool
    def generate_keypair(name, email, passphrase, algorithm) -> KeyBundle
    def sign(data: bytes, private_key_armor: str, passphrase: str) -> str
    def verify(data: bytes, signature_armor: str, public_key_armor: str) -> bool
    def fingerprint_from_armor(key_armor: str) -> str
    def add_pqc_subkeys(private_key_armor, passphrase, cipher_suite) -> KeyBundle
```

### 3.6 Honesty / error semantics required by callers
- Bad armor → a catchable exception (callers wrap broadly; `peers.py` re-raises
  `ValueError`). Provide a typed `SkPgpError`.
- `verify_*` must **never raise on a bad signature** in the capauth/skchat paths
  that `return False` on exception — but raising is acceptable where callers
  catch (most do). Safest: return bool, raise only on malformed inputs.
- Fingerprints returned **normalized** (UPPER, no spaces) so callers can drop the
  `.replace(" ","").upper()` dance over time (keep accepting it for parity).
- Support BOTH v4 (40-hex) and v6/RFC9580 (64-hex) fingerprints.

---

## 4. Migration worklist (additive, in order)

Principle: **additive + behavior-preserving**. sk_pgp lands as a new optional
backend/branch behind a feature flag; PGPy stays until parity is proven per repo.
No call site changes its *contract* — only the implementation behind it.

**Phase 0 — sk_pgp parity (this repo).** Build + test the API in §3 against
golden vectors generated by today's PGPy/`sq` (sign→verify, encrypt→decrypt,
fingerprint, keygen) for both classical (Ed25519/RSA) and PQC (mldsa87-ed448,
mldsa65-ed25519) suites. Acceptance = byte-compatible verify of existing
PGPy-produced sigs and vice-versa.

**Phase 1 — capauth backend (lowest blast radius, highest value).**
1. `src/capauth/crypto/skpgp_backend.py` — new `SkPgpBackend` (§3.5). Additive;
   registers alongside `pgpy_backend.py` / `sequoia_backend.py`.
2. Route `generate_keypair / sign / verify / fingerprint_from_armor /
   add_pqc_subkeys` through sk_pgp (in-process) instead of the `sq` subprocess.
   This is the first place sk_pgp earns its keep: **PQC signing without shelling
   `sq`.**
3. `src/capauth/did.py` (106–124): swap RSA-number extraction to
   `cert.rsa_public_numbers()` / `ed25519_public_bytes()`.
4. Keep `PGPyBackend` + `SequoiaBackend` selectable for fallback/comparison.

**Phase 2 — skcomms signing/identity (transport auth core).**
5. `src/skcomms/signing.py` — `EnvelopeSigner` (86–109) + `EnvelopeVerifier`
   (263–331) detached sign/verify → sk_pgp. (Hybrid path already non-PGPy.)
6. `src/skcomms/grants.py` (266–333) — consent-token sign/verify → sk_pgp
   (reuses the signer's key handle, same as today).
7. `src/skcomms/peers.py` (111) + `nostr_discovery.py` (217) — `fingerprint_*`
   → `Cert.from_bytes(...).fingerprint`.
8. `src/skcomms/capauth_validator.py` (63–389) — load-by-fingerprint, detached
   verify over str payloads, and **retire the `gpg --export` subprocess**
   (319–331) in favor of sk_pgp keyring/`Cert.from_bytes`.

**Phase 3 — skcomms + skchat message crypto (encrypt/decrypt).**
9. `src/skcomms/crypto.py` (172–334) — encrypt/decrypt/sign/verify payload.
10. `src/skchat/crypto.py` (133–672) — `ChatCrypto` + module helpers.
11. `src/skchat/files.py` (271–441) + `src/skchat/group.py` (1090–1124) — key
    wrap/unwrap. **Bonus:** these are the HNDL-exposed classical wraps flagged in
    skchat's CLAUDE.md; sk_pgp's PQC `encrypt`/`add_pqc_subkeys` enables the
    hybrid X25519+ML-KEM-768 target here.
12. Sync the `skchat/.claude/worktrees/pqc-q4/` mirror (or delete the worktree).

**Phase 4 — tests + cutover.**
13. Point test fixtures (skcomms/tests, skchat/tests `conftest.py`) at sk_pgp's
    cheap-suite `generate(...)`; keep RSA-1024/2048 fixtures runnable.
14. Flip the default backend to sk_pgp per repo once its parity suite is green;
    leave PGPy installable as a fallback for one release, then drop the PGPy and
    `sq`/`gpg` subprocess dependencies.

**Out of scope (no PGPy):** `skcomms.pqsig` (Ed25519+ML-DSA-65 hybrid envelope
sigs), `skcomms.pqkem`/`pqdm` (X25519+ML-KEM-768 sealing), `skcomms.tofu`
(opaque-string fingerprint store). sk_pgp should *converge* with pqsig/pqkem but
does not replace them in this audit.
