"""Phase-0.1 tests for the newly real-bound surface (run after a wheel build):

  * inline (attached-signature) sign  -> ``Key.sign_inline``
  * inline verify + embedded-data    -> ``Cert.verify_inline``
  * ML-KEM (FIPS 203) encrypt         -> ``Cert.encrypt``
  * ML-KEM decrypt                    -> ``Key.decrypt``

Honesty: these are post-quantum / quantum-resistant operations, never
"quantum-proof". The cheap classical ``cv25519`` suite is used for the fast
round-trips (PQC keygen is slow); a single ``@slow`` case exercises the real
ML-KEM-1024+X448 composite KEM path end to end.
"""

import pytest

sk_pgp = pytest.importorskip("sk_pgp")


# --------------------------------------------------------------------------
# inline (attached) sign + verify
# --------------------------------------------------------------------------

def test_inline_sign_verify_roundtrip():
    key = sk_pgp.Key.generate("Inline <i@example.com>", "cv25519")
    signed = key.sign_inline(b"attached payload")
    valid, data = key.cert.verify_inline(signed)
    assert valid is True
    assert data == b"attached payload"  # embedded data recovered verbatim


def test_inline_verify_wrong_key_rejects():
    a = sk_pgp.Key.generate("A <a@example.com>", "cv25519")
    b = sk_pgp.Key.generate("B <b@example.com>", "cv25519")
    signed = a.sign_inline(b"from-a")
    # Verifying against the wrong cert must NOT validate (and must not lie about
    # the data). Rejection may surface as (False, ...) or a PgpError — both are
    # honest "rejected".
    try:
        valid, _ = b.cert.verify_inline(signed)
        assert valid is False
    except sk_pgp.PgpError:
        pass


def test_inline_verify_tamper_rejects():
    key = sk_pgp.Key.generate("T <t@example.com>", "cv25519")
    signed = bytearray(key.sign_inline(b"original-message"))
    # Corrupt a byte inside the armored body (skip the BEGIN header line).
    nl = signed.index(b"\n\n") if b"\n\n" in signed else 40
    idx = nl + 10
    signed[idx] = signed[idx] ^ 0x01
    try:
        valid, _ = key.cert.verify_inline(bytes(signed))
        assert valid is False
    except sk_pgp.PgpError:
        pass  # malformed-after-tamper is also a valid rejection


def test_inline_protected_key_requires_password():
    key = sk_pgp.Key.generate("P <p@example.com>", "cv25519", password="s3cret")
    with pytest.raises(sk_pgp.PgpError):
        key.sign_inline(b"x")  # no password
    signed = key.sign_inline(b"x", password="s3cret")
    valid, data = key.cert.verify_inline(signed)
    assert valid is True and data == b"x"


# --------------------------------------------------------------------------
# ML-KEM encrypt + decrypt
# --------------------------------------------------------------------------

def test_kem_encrypt_decrypt_roundtrip():
    key = sk_pgp.Key.generate("Enc <e@example.com>", "cv25519")
    ct = key.cert.encrypt(b"top secret")
    assert b"BEGIN PGP MESSAGE" in ct
    pt = key.decrypt(ct)
    assert pt == b"top secret"


def test_kem_decrypt_wrong_key_rejects():
    a = sk_pgp.Key.generate("RecipA <ra@example.com>", "cv25519")
    b = sk_pgp.Key.generate("RecipB <rb@example.com>", "cv25519")
    ct = a.cert.encrypt(b"for-a-only")
    with pytest.raises(sk_pgp.PgpError):
        b.decrypt(ct)  # b holds no matching KEM/ECDH subkey


def test_kem_protected_key_roundtrip():
    key = sk_pgp.Key.generate("PEnc <pe@example.com>", "cv25519", password="pw9")
    ct = key.cert.encrypt(b"sealed")
    with pytest.raises(sk_pgp.PgpError):
        key.decrypt(ct)  # secret KEM key is locked
    pt = key.decrypt(ct, password="pw9")
    assert pt == b"sealed"


@pytest.mark.slow
def test_pqc_mlkem_encrypt_decrypt_roundtrip():
    # Real FIPS-203 ML-KEM-1024+X448 composite KEM (carried by the
    # mldsa87-ed448 cert). Hybrid = sealed under BOTH legs.
    key = sk_pgp.Key.generate("PQEnc <pqe@example.com>", "mldsa87-ed448")
    assert key.is_post_quantum is True
    ct = key.cert.encrypt(b"pq-sealed")
    assert key.decrypt(ct) == b"pq-sealed"
