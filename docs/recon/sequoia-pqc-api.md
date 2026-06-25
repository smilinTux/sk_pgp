# sequoia-openpgp 2.2.0-pqc.1 — Exact Rust API for sk_pgp

**Status:** RECON / SPEC. This documents the exact Rust symbols the sk_pgp PyO3
bindings must call, quoted from the cached source our `sq 1.4.0-pqc.1` was built
from. Do not guess — every type/function below was read from:

- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sequoia-openpgp-2.2.0-pqc.1`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sequoia-sq-1.4.0-pqc.1` (usage reference)

This crate ships **v6/RFC9580** (`Profile::RFC9580`), **ML-DSA-87+Ed448**,
**ML-DSA-65+Ed25519**, **ML-KEM-1024+X448 / ML-KEM-768+X25519**, and **SLH-DSA**.

Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA),
RFC 8032 (Ed25519/Ed448), RFC 9580 (OpenPGP v6), draft-ietf-openpgp-pqc
(composite PQC). Honesty: these are **post-quantum / quantum-resistant**
algorithms, **never** "quantum-proof". Hybrid composite signatures are valid
iff **both** legs (PQ + classical) verify — that semantics is enforced inside
sequoia's `MLDSA*_*` algorithms; we bind it, we never hand-roll it.

---

## 0. Cargo dependency + build environment

### Cargo.toml (the bindings crate)

```toml
[dependencies]
# Pinned to the exact PQC fork our sq binary was built from.
sequoia-openpgp = { version = "=2.2.0-pqc.1", default-features = false, features = ["crypto-openssl"] }
anyhow = "1"       # sequoia's Result<T> = std::result::Result<T, anyhow::Error>
pyo3   = { version = "0.22", features = ["extension-module", "abi3-py38"] }
```

Notes verified from `sequoia-openpgp-2.2.0-pqc.1/Cargo.toml`:
- `version = "2.2.0-pqc.1"`. Pin with `=` so cargo never resolves to a
  non-PQC release.
- `[features]` confirms `crypto-openssl = ["dep:ossl"]`. The default feature set
  is `default = ["compression", "crypto-nettle"]`, so we **must** pass
  `default-features = false` (drops nettle) and explicitly enable
  `crypto-openssl`. This matches exactly how sq was built:
  `--no-default-features --features crypto-openssl`.
- `crate::Result<T>` is `std::result::Result<T, anyhow::Error>` (`src/lib.rs:244`),
  so depend on `anyhow` to construct/propagate errors at the FFI boundary.

### Build env (matches the sq build; linuxbrew OpenSSL 3.6.2)

```sh
export OPENSSL_DIR=/home/linuxbrew/.linuxbrew/opt/openssl@3
export BINDGEN_EXTRA_CLANG_ARGS="-I${OPENSSL_DIR}/include"
# liboqs 0.14 is pulled in by the crypto-openssl backend; system copy:
#   ~/.local/lib/liboqs.so   (ensure on the linker/runtime path if not vendored)
source ~/.cargo/env   # rustc 1.96.0
```

In `pyproject.toml` for maturin, surface these via `[tool.maturin]` or a
`build.env` shim so wheels build reproducibly.

---

## 1. Parse a `Cert` (public) and a `TSK` (secret key) from ASCII-armored bytes

**Module:** `sequoia_openpgp::Cert` (`src/cert.rs`), trait
`sequoia_openpgp::parse::Parse` (`src/parse.rs:297`).

A `Cert` holds whatever key material is present — armored input may be a public
cert OR a transferable secret key (TSK). There is **no distinct parse type** for
a TSK: you parse a `Cert` and the secret packets ride along. ASCII-armor is
auto-detected by `Parse::from_bytes` (it sniffs armor vs binary). `Cert` also
implements `std::str::FromStr` (`src/cert.rs:641`).

```rust
use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::parse::Parse;   // brings Cert::from_bytes / from_reader into scope

// Works for both PUBLIC KEY BLOCK and PRIVATE KEY BLOCK armor.
let cert: Cert = Cert::from_bytes(armored_bytes)?;

// To assert it actually carries secret material (i.e. is a TSK):
let has_secret = cert.is_tsk();   // src/cert.rs (bool)
```

Key API:
- `Cert::from_bytes(&[u8]) -> Result<Cert>` (via `Parse`).
- `Cert::from_reader(impl Read) -> Result<Cert>` (via `Parse`).
- `Cert::is_tsk(&self) -> bool` — true iff at least one key has secret material.

For sk_pgp, expose one Python entry that parses bytes into an internal `Cert`
handle; a separate `is_secret`/`has_secret_key` property surfaces `is_tsk()`.

---

## 2. Generate a v6/RFC9580 key — ML-DSA-87+Ed448 and ML-DSA-65+Ed25519

**Modules:** `sequoia_openpgp::cert::CertBuilder` (`src/cert/builder.rs`),
`sequoia_openpgp::cert::CipherSuite` (`src/cert/builder.rs:68`),
`sequoia_openpgp::Profile` (`src/lib.rs:234`),
`sequoia_openpgp::packet::prelude::KeyFlags`,
`sequoia_openpgp::packet::UserID`,
`sequoia_openpgp::crypto::Password`.

### The enums (quoted from source)

`Profile` (`src/lib.rs:234`):
```rust
pub enum Profile {
    RFC9580,            // v6
    RFC4880,            // v4 (default)
}
```

`CipherSuite` (`src/cert/builder.rs:68`) — the PQC variants are exactly:
```rust
pub enum CipherSuite {
    Cv25519, RSA3k, P256, P384, P521, RSA2k, RSA4k,
    MLDSA65_Ed25519,    // sig ML-DSA-65+Ed25519, KEM ML-KEM-768+X25519  (L3)
    MLDSA87_Ed448,      // sig ML-DSA-87+Ed448,   KEM ML-KEM-1024+X448   (L5)
}
```
So our two cipher-suite strings map directly:
- `"mldsa87-ed448"`  → `CipherSuite::MLDSA87_Ed448`
- `"mldsa65-ed25519"`→ `CipherSuite::MLDSA65_Ed25519`
- classical `"cv25519"` → `CipherSuite::Cv25519`, `"rsa3072"` → `RSA3k`, etc.

(Note the doc comment at `builder.rs:88` mislabels it "MLDSA78" — the variant
and the `PublicKeyAlgorithm::MLDSA87_Ed448` check at `builder.rs:168` confirm it
is **ML-DSA-87**.)

### The builder calls (verified against `sq` key generate, `commands/key/generate.rs`)

`sq` builds the cert like this (`generate.rs:57`, `:96`, `:183`):
```rust
let mut builder = CertBuilder::new()
    .set_profile(command.profile.into())?;          // RFC9580 → v6
builder = builder.add_userid(uid.clone());          // per user id
builder = builder.set_creation_time(sq.time);
builder = builder.set_validity_period(duration);    // None = no expiry
builder = builder.set_cipher_suite(/* CipherSuite */);
builder = builder.set_primary_key_flags(KeyFlags::empty().set_certification());
builder = builder.add_subkey(KeyFlags::empty().set_signing(), None, None);
builder = builder.add_subkey(KeyFlags::empty()
            .set_transport_encryption().set_storage_encryption(), None, None);
builder = builder.set_password(Some(pw));            // optional protection
let (cert, _rev): (Cert, Signature) = builder.generate()?;
```

Relevant signatures (from `src/cert/builder.rs`):
- `CertBuilder::new() -> Self` (`:454`)
- `set_profile(self, Profile) -> Result<Self>` (`:722`) — **how you get v6**.
- `set_cipher_suite(self, CipherSuite) -> Self` (`:647`)
- `add_userid<U: Into<UserID>>(self, U) -> Self` (`:802`)
- `set_creation_time<T: Into<Option<SystemTime>>>(self, T) -> Self` (`:585`)
- `set_validity_period<T: Into<Option<Duration>>>(self, T) -> Self` (`:1523`)
- `set_primary_key_flags(self, KeyFlags) -> Self` (`:1450`)
- `add_signing_subkey(self) -> Self` (`:1115`) / `add_subkey(self, KeyFlags, validity, cs) -> Self` (`:1323`)
- `add_transport_encryption_subkey(self) -> Self` (`:1153`)
- `set_password(self, Option<Password>) -> Self` (`:1478`)
- `generate(self) -> Result<(Cert, Signature)>` (`:1589`)

Convenience: `CertBuilder::general_purpose<U>(userids: U) -> Self` (`:507`)
seeds sign+encrypt subkeys in one shot, but to force v6+PQC we chain
`set_profile(RFC9580)` + `set_cipher_suite(MLDSA87_Ed448)` ourselves (the
`general_purpose` default is v4/Cv25519).

### Minimal snippet (sk_pgp keygen)

```rust
use sequoia_openpgp as openpgp;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::Profile;
use openpgp::packet::prelude::KeyFlags;
use openpgp::crypto::Password;

fn generate(uid: &str, password: Option<&str>) -> openpgp::Result<openpgp::Cert> {
    let mut b = CertBuilder::new()
        .set_profile(Profile::RFC9580)?                 // v6 / 64-hex fingerprint
        .set_cipher_suite(CipherSuite::MLDSA87_Ed448)   // L5 PQC composite
        .add_userid(uid)
        .set_validity_period(None)                      // no expiry
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_subkey(KeyFlags::empty().set_signing(), None, None)
        .add_subkey(KeyFlags::empty()
            .set_transport_encryption().set_storage_encryption(), None, None);
    if let Some(p) = password {
        b = b.set_password(Some(Password::from(p)));
    }
    let (cert, _rev) = b.generate()?;
    Ok(cert)
}
```

To serialize the resulting TSK to armored ASCII for return to Python, see §5
(`cert.as_tsk().armored()`).

`CipherSuite::is_supported(&self) -> Result<()>` (`:116`) can be called first to
fail fast with a clear error if the crypto-openssl/liboqs backend lacks the
algorithm.

---

## 3. Make a DETACHED signature over bytes (possibly password-protected key)

**Modules:** `sequoia_openpgp::serialize::stream::{Message, Signer}`
(`src/serialize/stream.rs`), `sequoia_openpgp::policy::StandardPolicy`,
`sequoia_openpgp::crypto::{KeyPair, Password}`,
key selection via `cert.keys()` (`src/cert/amalgamation/key.rs`).

### Selecting + unlocking the signing key

From the streaming-sign doc example (`stream.rs:880`) the canonical selector is:
```rust
cert.keys().secret()
    .with_policy(p, None).supported().alive().revoked(false).for_signing()
    .nth(0).unwrap()
    .key().clone().into_keypair()?
```
- `.secret()` keeps only keys with secret material.
- `.with_policy(&StandardPolicy, None)` applies the policy / time.
- `.supported().alive().revoked(false).for_signing()` filter to a usable sig key
  (`for_signing` predicate at `cert/amalgamation/key.rs:3091`).
- `Key::into_keypair(self) -> Result<KeyPair>` (`src/packet/key.rs:536`) — but
  this **fails if the secret is still encrypted**.

For a **password-protected** key, decrypt the secret first:
- `Key::is_encrypted(&self) -> bool` (`src/packet/key.rs:2195`)
- `Key::decrypt_secret(self, &Password) -> Result<Self>` (`src/packet/key.rs:596`)

```rust
let key = ka.key().clone();
let key = if key.secret().is_encrypted() {       // SecretKeyMaterial::is_encrypted
    key.decrypt_secret(&Password::from(pw))?
} else { key };
let mut keypair = key.into_keypair()?;
```
(`Key::secret(&self) -> &SecretKeyMaterial`, `src/packet/key.rs:481`;
`Password::from(&str)` / `From<String>` / `From<&[u8]>`,
`src/crypto/mod.rs:220-250`.)

### Producing the detached signature

`Signer::detached()` (`stream.rs:925`) switches the signer to detached mode; the
bytes written to the `Signer` are hashed but only the signature packet is
emitted. Wrap the sink in an `Armorer` for ASCII output.

```rust
use sequoia_openpgp as openpgp;
use openpgp::serialize::stream::{Message, Signer, Armorer};
use openpgp::policy::StandardPolicy;
use std::io::Write;

fn detached_sign(cert: &openpgp::Cert, data: &[u8], pw: Option<&str>)
    -> openpgp::Result<Vec<u8>>
{
    let p = &StandardPolicy::new();
    let ka = cert.keys().secret()
        .with_policy(p, None).supported().alive().revoked(false).for_signing()
        .nth(0).ok_or_else(|| anyhow::anyhow!("no signing-capable secret key"))?;
    let mut key = ka.key().clone();
    if key.secret().is_encrypted() {
        let pw = pw.ok_or_else(|| anyhow::anyhow!("key is protected; password required"))?;
        key = key.decrypt_secret(&openpgp::crypto::Password::from(pw))?;
    }
    let keypair = key.into_keypair()?;

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build()?;          // ASCII armor wrapper
        let mut signer = Signer::new(message, keypair)?
            .detached()
            .build()?;
        signer.write_all(data)?;
        signer.finalize()?;
    }
    Ok(sink)   // "-----BEGIN PGP SIGNATURE-----" ... armored detached sig
}
```

For a **binary** (non-armored) detached sig, drop the `Armorer::new(...)` line.
The composite hybrid (ML-DSA + Ed448) signing is performed transparently inside
`KeyPair` for the `MLDSA87_Ed448` algorithm — sk_pgp just selects the key.

Relevant signatures:
- `Message::new(impl Write) -> Message` (`stream.rs`)
- `Signer::new(Message, impl Signer/KeyPair) -> Result<Signer>` (`stream.rs`)
- `Signer::detached(self) -> Self` (`stream.rs:925`)
- `Signer::build(self) -> Result<Message>` (`stream.rs:1308`)
- `Armorer::new(Message) -> Armorer` / `.build() -> Result<Message>`

---

## 4. Verify a detached signature against a `Cert`

**Modules:** `sequoia_openpgp::parse::stream::{DetachedVerifierBuilder,
VerificationHelper, MessageStructure, MessageLayer}` (`src/parse/stream.rs`),
`sequoia_openpgp::policy::StandardPolicy`, `Parse` for byte ingestion.

`DetachedVerifierBuilder::from_bytes(sig) -> Result<...>` (via `Parse`,
`stream.rs:1461`), then `.with_policy(policy, time, helper)` yields a
`DetachedVerifier`, on which `verify_bytes(data)` / `verify_reader(r)` runs the
check (`stream.rs:1440`).

The `VerificationHelper` trait supplies the certs (`get_certs`) and adjudicates
the result (`check`). A signature is accepted only if `check` returns `Ok` and a
`VerificationResult` in the `SignatureGroup` is `Ok` — for the composite
`MLDSA87_Ed448` algorithm sequoia internally requires **both** the ML-DSA and
the Ed448 legs to verify (hybrid AND-semantics), so a single `Ok` here already
means "both legs valid".

```rust
use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, VerificationHelper, MessageStructure, MessageLayer,
};
use openpgp::policy::StandardPolicy;
use openpgp::KeyHandle;

struct H<'a>(&'a Cert);
impl<'a> VerificationHelper for H<'a> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.0.clone()])
    }
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                // accept iff at least one signature in the group verified
                if results.into_iter().any(|r| r.is_ok()) {
                    return Ok(());
                }
            }
        }
        Err(anyhow::anyhow!("no valid signature"))
    }
}

fn verify_detached(cert: &Cert, sig: &[u8], data: &[u8]) -> openpgp::Result<bool> {
    let p = &StandardPolicy::new();
    let mut v = DetachedVerifierBuilder::from_bytes(sig)?
        .with_policy(p, None, H(cert))?;
    match v.verify_bytes(data) {
        Ok(())  => Ok(true),
        Err(_)  => Ok(false),   // surface as False, or map to a Python exception
    }
}
```

Relevant signatures:
- `DetachedVerifierBuilder::from_bytes(&[u8]) -> Result<Self>` (Parse, `:1461`)
- `DetachedVerifierBuilder::with_policy(self, &dyn Policy, T, H) -> Result<DetachedVerifier<H>>` (`:1452`)
- `DetachedVerifier::verify_bytes(&mut self, &[u8]) -> Result<()>` (`:1442`)
- `enum MessageLayer::SignatureGroup { results: Vec<VerificationResult> }`

`StandardPolicy` will, by default, reject weak/legacy algorithms; for PQC keys
this is fine. If we ever load v4/legacy material we may need a relaxed policy.

---

## 5. Extract the public `Cert` from a TSK + armor it

**Module:** `sequoia_openpgp::Cert::strip_secret_key_material`
(`src/cert.rs`), armoring via `serialize::cert_armored` (`src/serialize/cert_armored.rs`).

- Public from secret: `Cert::strip_secret_key_material(self) -> Cert`
  (returns the cert with all secret packets removed). Verified present in
  `src/cert.rs` alongside `is_tsk`.
- Armor a **public** cert: `cert.armored()` (`cert_armored.rs:84`) →
  `impl Serialize + SerializeInto`; call `.to_vec()` →
  `-----BEGIN PGP PUBLIC KEY BLOCK-----`.
- Armor a **secret** TSK: `cert.as_tsk().armored()` (`cert_armored.rs:116`,
  `as_tsk` at `serialize/cert.rs:273`) → `-----BEGIN PGP PRIVATE KEY BLOCK-----`.

```rust
use openpgp::serialize::SerializeInto;   // brings .to_vec() into scope

// secret cert -> armored public key block
let public = cert.clone().strip_secret_key_material();
let public_armored: Vec<u8> = public.armored().to_vec()?;

// secret cert -> armored TSK (private key block)
let tsk_armored: Vec<u8> = cert.as_tsk().armored().to_vec()?;
```

Relevant signatures:
- `Cert::strip_secret_key_material(self) -> Cert` (`src/cert.rs`)
- `Cert::as_tsk(&self) -> TSK` (`src/serialize/cert.rs:273`),
  `Cert::into_tsk(self) -> TSK<'static>` (`:282`)
- `Cert::armored(&self) -> impl Serialize + SerializeInto` (`cert_armored.rs:84`)
- `TSK::armored(self) -> impl Serialize + SerializeInto` (`cert_armored.rs:116`)
- `TSK::emit_secret_key_stubs(self, bool) -> Self` (`serialize/cert.rs:503`) and
  `TSK::set_filter<P>(self, P) -> Self` (`:424`) — for offline-primary / subkey
  export variants if sk_pgp later needs them.
- `SerializeInto::to_vec(&self) -> Result<Vec<u8>>` (`src/serialize.rs:419`).

---

## 6. Fingerprint (64-hex for v6)

**Module:** `sequoia_openpgp::Fingerprint` (`src/fingerprint.rs`).

`Cert::fingerprint(&self) -> Fingerprint` (`src/cert.rs:2141`) returns the
**primary key** fingerprint. For a v6/RFC9580 key this is a 32-byte SHA-256
fingerprint → **64 hex chars**; for v4 it is 40 hex chars. The same method
exists on `ValidCert` (`:4311`) and per-key via `Key::fingerprint`
(`src/packet/key.rs:969`).

Rendering:
- `Fingerprint::to_hex(&self) -> String` (`:224`) — compact, uppercase, no
  spaces (use this for the canonical 64-hex id).
- `Fingerprint::to_spaced_hex(&self) -> String` (`:266`) — human-grouped.
- `impl Display for Fingerprint` (`:70`) — also produces hex.

```rust
let fpr = cert.fingerprint().to_hex();   // e.g. 64 hex chars for v6
```

This mirrors `capauth`'s `fingerprint_from_armor` (parse → `.fingerprint()` →
hex), but in-process instead of shelling to `sq`.

---

## 7. ML-KEM encrypt / decrypt (note the API even if we defer it)

**Modules:** encrypt — `serialize::stream::{Encryptor, Recipient, LiteralWriter}`
(`src/serialize/stream.rs`); decrypt — `parse::stream::{DecryptorBuilder,
DecryptionHelper, VerificationHelper}` (`src/parse/stream.rs`).

PQC KEM is transparent: a `MLDSA87_Ed448` cert carries an `MLKEM1024_X448`
encryption subkey (`MLDSA65_Ed25519` carries `MLKEM768_X25519` —
`PublicKeyAlgorithm` variants at `src/crypto/types/public_key_algorithm.rs:79`).
You select encryption-capable keys exactly like any ECDH/RSA key; sequoia routes
to the composite KEM by algorithm. **draft-ietf-openpgp-pqc** composite KEM.

### Encrypt (recipient = the PQC cert)

From the streaming-encrypt example (`stream.rs:89`):
```rust
use openpgp::serialize::stream::{Message, Encryptor, LiteralWriter, Recipient};
use openpgp::policy::StandardPolicy;
use std::io::Write;

let p = &StandardPolicy::new();
let recipients = recipient.keys().with_policy(p, None)
    .supported().alive().revoked(false).for_transport_encryption();  // KEM subkey

let mut sink = Vec::new();
let message = Message::new(&mut sink);
let message = Encryptor::for_recipients(message, recipients).build()?;
let mut w = LiteralWriter::new(message).build()?;
w.write_all(plaintext)?;
w.finalize()?;
```
- `Recipient` struct (`stream.rs:2166`), `Recipient::new(...)` (`:2215`).
- `Encryptor::for_recipients(Message, R) -> Encryptor` then `.build()`.
- key selector `for_transport_encryption()` / `for_storage_encryption()`
  (`cert/amalgamation/key.rs:3218` / `:3171`).

### Decrypt (we hold the TSK)

```rust
use openpgp::parse::stream::{DecryptorBuilder, DecryptionHelper, VerificationHelper};
// Implement DecryptionHelper::decrypt(&mut self, &[PKESK], &[SKESK], sym, &mut FnMut...)
// to try our secret KEM key(s); VerificationHelper for any signatures inside.
let mut d = DecryptorBuilder::from_bytes(ciphertext)?
    .with_policy(p, None, helper)?;
std::io::copy(&mut d, &mut plaintext_sink)?;
```
- `DecryptorBuilder::from_bytes(&[u8]) -> Result<Self>` (Parse).
- `DecryptionHelper::decrypt(...)` (`parse/stream.rs:944`) — where you unlock the
  secret KEM subkey (`decrypt_secret(&Password)` if protected, then
  `into_keypair()`) and call `pkesk.decrypt(&mut keypair, sym)`.

**sk_pgp v1 may defer encrypt/decrypt** (sign/verify/cert are the priority for
skcomms/capauth), but the binding shape is the same `keys()...for_*()` selector
+ stream builder, so it is cheap to add.

---

## Symbol quick-reference (module paths)

| Op | Type / fn | Path |
|----|-----------|------|
| Parse | `Cert::from_bytes`, `Parse` trait | `cert.rs`, `parse.rs:297` |
| TSK detect | `Cert::is_tsk` | `cert.rs` |
| Profile v6 | `Profile::RFC9580` | `lib.rs:234` |
| Suites | `CipherSuite::MLDSA87_Ed448` / `MLDSA65_Ed25519` | `cert/builder.rs:68` |
| Keygen | `CertBuilder::{new,set_profile,set_cipher_suite,add_userid,set_password,generate}` | `cert/builder.rs` |
| Unlock | `Key::is_encrypted`, `decrypt_secret`, `into_keypair` | `packet/key.rs:2195/596/536` |
| Password | `crypto::Password` (`From<&str>` etc.) | `crypto/mod.rs:217` |
| Sign | `stream::Signer::{new,detached,build}`, `Armorer` | `serialize/stream.rs:925/1308` |
| Verify | `stream::DetachedVerifierBuilder`, `VerificationHelper`, `MessageLayer::SignatureGroup` | `parse/stream.rs:1455` |
| Pub from TSK | `Cert::strip_secret_key_material`, `as_tsk` | `cert.rs`, `serialize/cert.rs:273` |
| Armor | `Cert::armored`, `TSK::armored`, `SerializeInto::to_vec` | `serialize/cert_armored.rs:84/116`, `serialize.rs:419` |
| Fingerprint | `Cert::fingerprint`, `Fingerprint::to_hex` | `cert.rs:2141`, `fingerprint.rs:224` |
| KEM algos | `PublicKeyAlgorithm::{MLKEM1024_X448,MLKEM768_X25519}` | `crypto/types/public_key_algorithm.rs:79` |
| Encrypt | `stream::{Encryptor,Recipient,LiteralWriter}` | `serialize/stream.rs:2166` |
| Decrypt | `parse::stream::{DecryptorBuilder,DecryptionHelper}` | `parse/stream.rs:944` |

All filters/selectors hang off `cert.keys()` →
`.secret().with_policy(p, t).supported().alive().revoked(false).for_signing()`
(or `.for_transport_encryption()`), defined in `src/cert/amalgamation/key.rs`.
