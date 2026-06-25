//! sk_pgp — sovereign post-quantum OpenPGP for Python.
//!
//! PyO3 bindings to the PQC-capable `sequoia-openpgp 2.2.0-pqc.1` (the exact crate
//! our `sq 1.4.0-pqc.1` was built from). This is the **PGPy replacement**: it can
//! load v6/RFC9580 + post-quantum (ML-DSA / ML-KEM) OpenPGP keys, sign (incl. the
//! ML-DSA-87+Ed448 and ML-DSA-65+Ed25519 composites), verify, and handle certs —
//! operations PGPy and gpg 2.4 cannot perform — in-process, instead of shelling
//! out to `sq`.
//!
//! Honesty: these are **post-quantum / quantum-resistant** algorithms, never
//! "quantum-proof". A hybrid composite signature is valid iff **both** legs
//! (PQ + classical) verify — that AND-semantics is enforced inside sequoia for the
//! composite algorithms; we bind it, we never hand-roll crypto.
//!
//! Standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA),
//! RFC 8032 (EdDSA), RFC 9580 (OpenPGP v6), draft-ietf-openpgp-pqc.

use std::io::Write as _;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::Password;
use openpgp::packet::prelude::KeyFlags;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::serialize::Serialize;
use openpgp::Profile;

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

// A named Python exception so callers can `except sk_pgp.PgpError`.
create_exception!(_sk_pgp, PgpError, PyException, "Error from the sk_pgp OpenPGP engine.");

/// Map any displayable error into our Python exception.
fn to_py_err<E: std::fmt::Display>(e: E) -> PyErr {
    PgpError::new_err(e.to_string())
}

/// Uniform marker for binding methods that are intentionally not implemented yet
/// in this skeleton. Returns a catchable `PgpError` rather than panicking.
fn todo_err(what: &str) -> PyErr {
    PgpError::new_err(format!("sk_pgp: {what} is not implemented yet (skeleton TODO)"))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// True if any key in the cert uses an ML-DSA / ML-KEM (post-quantum) algorithm.
///
/// Best-effort: matches on the algorithm's Debug rendering so we don't pin the
/// exact `PublicKeyAlgorithm` variant identifiers (which the parent build can
/// tighten later against `openpgp::types::PublicKeyAlgorithm`).
fn cert_is_post_quantum(cert: &openpgp::Cert) -> bool {
    cert.keys().any(|ka| {
        let a = format!("{:?}", ka.key().pk_algo()).to_uppercase();
        a.contains("MLDSA") || a.contains("MLKEM") || a.contains("ML-DSA") || a.contains("ML-KEM")
    })
}

/// `VerificationHelper` that trusts exactly one cert (the verifier's pubkey).
struct OneCertHelper {
    cert: openpgp::Cert,
}

impl VerificationHelper for OneCertHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                // For composite PQC algorithms sequoia requires BOTH legs to
                // verify before yielding an Ok here, so a single Ok already
                // means "both legs valid".
                if results.into_iter().any(|r| r.is_ok()) {
                    return Ok(());
                }
            }
        }
        Err(anyhow::anyhow!("no valid signature"))
    }
}

// ---------------------------------------------------------------------------
// Cert — public certificate (transferable pubkey)
// ---------------------------------------------------------------------------

/// A parsed OpenPGP certificate (public half). Mirrors PGPy's `PGPKey` pubkey
/// surface used by skcomms / skchat / capauth.
#[pyclass]
#[derive(Clone)]
pub struct Cert {
    pub(crate) cert: openpgp::Cert,
}

#[pymethods]
impl Cert {
    /// Parse a cert from raw OpenPGP bytes (armored or binary — auto-detected).
    /// REAL-BOUND.  ⇄ `PGPKey.from_blob`.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(data).map_err(to_py_err)?;
        Ok(Cert { cert })
    }

    /// Parse from an ASCII-armored string. REAL-BOUND.
    #[staticmethod]
    fn from_armor(armor: &str) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(armor.as_bytes()).map_err(to_py_err)?;
        Ok(Cert { cert })
    }

    /// Parse from a file path. REAL-BOUND.  ⇄ `PGPKey.from_file`.
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let data = std::fs::read(path).map_err(to_py_err)?;
        let cert = openpgp::Cert::from_bytes(&data).map_err(to_py_err)?;
        Ok(Cert { cert })
    }

    /// Primary-key fingerprint, UPPER hex, no spaces.
    /// 40 hex (v4) / 64 hex (v6/RFC9580). REAL-BOUND.
    #[getter]
    fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    /// True if this cert carries an ML-DSA / ML-KEM component. REAL-BOUND (best-effort).
    #[getter]
    fn is_post_quantum(&self) -> bool {
        cert_is_post_quantum(&self.cert)
    }

    /// True if this cert actually carries secret key material (is a TSK). REAL-BOUND.
    #[getter]
    fn has_secret_key(&self) -> bool {
        self.cert.is_tsk()
    }

    /// ASCII-armored serialization (PGP PUBLIC KEY BLOCK). REAL-BOUND.  ⇄ `str(key.pubkey)`.
    fn to_armor(&self) -> PyResult<String> {
        let mut buf = Vec::new();
        self.cert.armored().serialize(&mut buf).map_err(to_py_err)?;
        String::from_utf8(buf).map_err(to_py_err)
    }

    /// Binary (non-armored) serialization as Python `bytes`. REAL-BOUND.
    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut buf = Vec::new();
        self.cert.serialize(&mut buf).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Verify an armored/binary DETACHED signature over `data`. REAL-BOUND.
    /// Returns a bool; raises only on malformed signature bytes. Both legs of a
    /// hybrid composite must verify for this to return True.  ⇄ `pub.verify(...)`.
    #[pyo3(signature = (sig, data))]
    fn verify_detached(&self, sig: &[u8], data: &[u8]) -> PyResult<bool> {
        let p = StandardPolicy::new();
        let helper = OneCertHelper { cert: self.cert.clone() };
        let mut v = DetachedVerifierBuilder::from_bytes(sig)
            .map_err(to_py_err)?
            .with_policy(&p, None, helper)
            .map_err(to_py_err)?;
        match v.verify_bytes(data) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// `str(cert)` → armored cert (pysequoia convention).
    fn __str__(&self) -> PyResult<String> {
        self.to_armor()
    }

    // -- DID / JWK support (capauth/did.py) — TODO-STUBBED -----------------

    /// RSA public params `(n, e)` for JWK emission. TODO-STUB.
    /// Needs `key.pubkey.public_key` material extraction; the exact sequoia
    /// `mpi::PublicKey::RSA { n, e }` access path is not yet pinned in recon.
    fn rsa_public_numbers(&self) -> PyResult<(u64, u64)> {
        Err(todo_err("Cert.rsa_public_numbers"))
    }

    /// Raw Ed25519 public point for JWK emission. TODO-STUB.
    fn ed25519_public_bytes<'py>(&self, _py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Err(todo_err("Cert.ed25519_public_bytes"))
    }

    /// Encrypt to this cert's encryption (KEM) subkey. TODO-STUB.
    /// Shape: `serialize::stream::{Encryptor, Recipient, LiteralWriter}` over
    /// `keys()...for_transport_encryption()` (recon §7); deferred in v1.
    #[pyo3(signature = (_plaintext, cipher = "AES256"))]
    fn encrypt<'py>(
        &self,
        _py: Python<'py>,
        _plaintext: &[u8],
        cipher: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let _ = cipher;
        Err(todo_err("Cert.encrypt"))
    }

    /// Verify an INLINE-signed message, returning (valid, embedded_data). TODO-STUB.
    fn verify_inline<'py>(
        &self,
        _py: Python<'py>,
        _signed: &[u8],
    ) -> PyResult<(bool, Bound<'py, PyBytes>)> {
        Err(todo_err("Cert.verify_inline"))
    }
}

// ---------------------------------------------------------------------------
// Key — secret key material (signer / decrypter)
// ---------------------------------------------------------------------------

/// An OpenPGP key holding secret material (a TSK). Mirrors PGPy's `PGPKey`
/// private-key surface (sign / unlock / decrypt / generate).
#[pyclass]
#[derive(Clone)]
pub struct Key {
    pub(crate) cert: openpgp::Cert,
}

#[pymethods]
impl Key {
    /// Parse a secret key from raw OpenPGP bytes (armored or binary). REAL-BOUND.
    /// ⇄ `PGPKey.from_blob(priv)`.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let cert = openpgp::Cert::from_bytes(data).map_err(to_py_err)?;
        if !cert.is_tsk() {
            return Err(PgpError::new_err(
                "sk_pgp.Key.from_bytes: no secret key material (parse as Cert instead)",
            ));
        }
        Ok(Key { cert })
    }

    /// Parse a secret key from a file path. REAL-BOUND.
    #[staticmethod]
    fn from_file(path: &str) -> PyResult<Self> {
        let data = std::fs::read(path).map_err(to_py_err)?;
        Self::from_bytes(&data)
    }

    /// Generate an OpenPGP keypair. REAL-BOUND.
    ///
    /// PQC suites (`mldsa87-ed448`, `mldsa65-ed25519`) are issued under
    /// `Profile::RFC9580` (v6) — the profile that carries the composite PQC
    /// algorithms. Reproduces `SequoiaBackend.generate_keypair`, in-process.
    ///
    /// * `userid`  — e.g. "Name <email>".
    /// * `suite`   — mldsa87-ed448 | mldsa65-ed25519 | cv25519/ed25519 | rsa4k | rsa3k.
    /// * `password`— protects the secret material (None = unprotected).
    /// * `profile` — "rfc9580"/"v6" (default) or "rfc4880"/"v4".
    #[staticmethod]
    #[pyo3(signature = (userid, suite = "mldsa87-ed448", password = None, profile = "rfc9580"))]
    fn generate(
        userid: &str,
        suite: &str,
        password: Option<&str>,
        profile: &str,
    ) -> PyResult<Self> {
        let cs = match suite {
            "mldsa87-ed448" => CipherSuite::MLDSA87_Ed448, // L5, ML-DSA-87+Ed448 / ML-KEM-1024+X448
            "mldsa65-ed25519" => CipherSuite::MLDSA65_Ed25519, // L3, ML-DSA-65+Ed25519 / ML-KEM-768+X25519
            "cv25519" | "ed25519" => CipherSuite::Cv25519,
            "rsa4k" | "rsa4096" => CipherSuite::RSA4k,
            "rsa3k" | "rsa3072" => CipherSuite::RSA3k,
            other => return Err(to_py_err(format!("unknown cipher suite: {other}"))),
        };
        let prof = match profile {
            "rfc9580" | "v6" => Profile::RFC9580,
            "rfc4880" | "v4" => Profile::RFC4880,
            other => return Err(to_py_err(format!("unknown profile: {other}"))),
        };

        let mut b = CertBuilder::new()
            .set_profile(prof)
            .map_err(to_py_err)?
            .set_cipher_suite(cs)
            .add_userid(userid)
            .set_validity_period(None::<std::time::Duration>)
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_subkey(
                KeyFlags::empty().set_signing(),
                None::<std::time::Duration>,
                None::<CipherSuite>,
            )
            .add_subkey(
                KeyFlags::empty().set_transport_encryption().set_storage_encryption(),
                None::<std::time::Duration>,
                None::<CipherSuite>,
            );
        if let Some(p) = password {
            b = b.set_password(Some(Password::from(p)));
        }
        let (cert, _rev) = b.generate().map_err(to_py_err)?;
        Ok(Key { cert })
    }

    /// The public half of this key. REAL-BOUND.  ⇄ `key.pubkey`.
    #[getter]
    fn cert(&self) -> Cert {
        Cert {
            cert: self.cert.clone().strip_secret_key_material(),
        }
    }

    /// Primary-key fingerprint (UPPER hex, no spaces). REAL-BOUND.
    #[getter]
    fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    /// True if this cert uses an ML-DSA / ML-KEM component. REAL-BOUND (best-effort).
    #[getter]
    fn is_post_quantum(&self) -> bool {
        cert_is_post_quantum(&self.cert)
    }

    /// True if any secret key in this cert is passphrase-encrypted. REAL-BOUND (best-effort).
    /// ⇄ `key.is_protected`.
    #[getter]
    fn is_protected(&self) -> bool {
        self.cert.keys().secret().any(|ka| ka.key().secret().is_encrypted())
    }

    /// ASCII-armored secret key (PGP PRIVATE KEY BLOCK). REAL-BOUND.  ⇄ `str(key)`.
    fn to_armor(&self) -> PyResult<String> {
        let mut buf = Vec::new();
        self.cert.as_tsk().armored().serialize(&mut buf).map_err(to_py_err)?;
        String::from_utf8(buf).map_err(to_py_err)
    }

    /// Create an armored DETACHED signature over `data`. REAL-BOUND.
    ///
    /// Selects a signing-capable secret key, unlocks it with `password` if the
    /// secret is encrypted, and streams a detached signature. The composite
    /// hybrid (ML-DSA + Ed448/Ed25519) signing happens transparently inside the
    /// `KeyPair` for the PQC suites. Reproduces `SequoiaBackend.sign`.
    /// ⇄ `key.unlock(pp)` + `key.sign(...)`.
    #[pyo3(signature = (data, password = None))]
    fn sign_detached<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        password: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let p = StandardPolicy::new();
        let ka = self
            .cert
            .keys()
            .secret()
            .with_policy(&p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .nth(0)
            .ok_or_else(|| PgpError::new_err("no signing-capable secret key"))?;

        let mut key = ka.key().clone();
        if key.secret().is_encrypted() {
            let pw = password
                .ok_or_else(|| PgpError::new_err("key is protected; password required"))?;
            key = key.decrypt_secret(&Password::from(pw)).map_err(to_py_err)?;
        }
        let keypair = key.into_keypair().map_err(to_py_err)?;

        let mut sink: Vec<u8> = Vec::new();
        {
            let message = Message::new(&mut sink);
            let message = Armorer::new(message).build().map_err(to_py_err)?;
            let mut signer = Signer::new(message, keypair)
                .map_err(to_py_err)?
                .detached()
                .build()
                .map_err(to_py_err)?;
            signer.write_all(data).map_err(to_py_err)?;
            signer.finalize().map_err(to_py_err)?;
        }
        Ok(PyBytes::new(py, &sink))
    }

    /// `str(key)` → armored secret key.
    fn __str__(&self) -> PyResult<String> {
        self.to_armor()
    }

    // -- TODO-STUBBED ------------------------------------------------------

    /// Inline-signed message (data + sig in one OpenPGP message). TODO-STUB.
    /// Shape: `Message::new -> Signer::new -> LiteralWriter -> write_all`.
    #[pyo3(signature = (_data, password = None))]
    fn sign_inline<'py>(
        &self,
        _py: Python<'py>,
        _data: &[u8],
        password: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let _ = password;
        Err(todo_err("Key.sign_inline"))
    }

    /// Decrypt an OpenPGP message with this key's KEM/ECDH subkey. TODO-STUB.
    /// Shape: `parse::stream::{DecryptorBuilder, DecryptionHelper}` (recon §7).
    #[pyo3(signature = (_ciphertext, password = None))]
    fn decrypt<'py>(
        &self,
        _py: Python<'py>,
        _ciphertext: &[u8],
        password: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let _ = password;
        Err(todo_err("Key.decrypt"))
    }

    /// Additively attach PQC subkeys (ML-DSA-87+Ed448 sign + ML-KEM-1024+X448
    /// enc), preserving the primary fingerprint. TODO-STUB.
    /// Needs the sequoia `KeyBuilder` / subkey-binding path (the in-process
    /// equivalent of `sq key subkey add`), not yet pinned in recon.
    #[pyo3(signature = (password = None, cipher_suite = "mldsa87-ed448"))]
    fn add_pqc_subkeys(&self, password: Option<&str>, cipher_suite: &str) -> PyResult<Key> {
        let _ = (password, cipher_suite);
        Err(todo_err("Key.add_pqc_subkeys"))
    }
}

// ---------------------------------------------------------------------------
// module
// ---------------------------------------------------------------------------

/// The compiled module. Name MUST equal the `[lib]` name (`_sk_pgp`).
#[pymodule]
fn _sk_pgp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Cert>()?;
    m.add_class::<Key>()?;

    // Named exception so Python can `except sk_pgp.PgpError`.
    m.add("PgpError", m.py().get_type::<PgpError>())?;

    // Supported cipher-suite ids.
    m.add("CIPHER_MLDSA87_ED448", "mldsa87-ed448")?; // L5 (ML-DSA-87+Ed448 / ML-KEM-1024+X448)
    m.add("CIPHER_MLDSA65_ED25519", "mldsa65-ed25519")?; // L3 (ML-DSA-65+Ed25519 / ML-KEM-768+X25519)
    m.add("CIPHER_CV25519", "cv25519")?; // classical fallback
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
