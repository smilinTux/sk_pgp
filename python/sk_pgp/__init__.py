"""sk_pgp — sovereign post-quantum OpenPGP for Python.

A PyO3 binding to the PQC-capable ``sequoia-openpgp 2.2.0-pqc.1`` (the exact
crate our ``sq 1.4.0-pqc.1`` binary was built from). This is the **PGPy
replacement**: it can load v6/RFC 9580 + post-quantum (ML-DSA / ML-KEM) OpenPGP
keys, sign (including the ML-DSA-87+Ed448 / ML-DSA-65+Ed25519 composites),
verify detached signatures, and handle certificates — operations PGPy and
gpg 2.4 cannot do — **in-process**, instead of shelling out to ``sq``.

Honesty: these are **post-quantum / quantum-resistant** algorithms, never
"quantum-proof". A hybrid composite signature is valid iff **both** legs
(post-quantum + classical) verify; sk_pgp binds sequoia/liboqs and never
hand-rolls crypto. Standards: FIPS 203/204/205, RFC 8032, RFC 9580,
draft-ietf-openpgp-pqc.

Quickstart::

    import sk_pgp

    key  = sk_pgp.Key.generate("Lumina <lumina@skworld.io>", "mldsa87-ed448",
                               password="hunter2")
    sig  = key.sign_detached(b"hello", password="hunter2")   # armored detached sig
    cert = key.cert                                          # public half
    assert cert.verify_detached(sig, b"hello") is True
    print(cert.fingerprint)                                  # 64 hex chars (v6)
    print(cert.is_post_quantum)                              # True
"""

from ._sk_pgp import (  # noqa: F401  (re-export the native symbols)
    CIPHER_CV25519,
    CIPHER_MLDSA65_ED25519,
    CIPHER_MLDSA87_ED448,
    Cert,
    Key,
    PgpError,
    __version__,
)

__all__ = [
    "Cert",
    "Key",
    "PgpError",
    "CIPHER_MLDSA87_ED448",
    "CIPHER_MLDSA65_ED25519",
    "CIPHER_CV25519",
    "__version__",
]
