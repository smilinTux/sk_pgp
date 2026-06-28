"""Phase-0 smoke tests for sk_pgp (run after `maturin develop`).

Covers the real-bound surface. PQC keygen is slow, so the round-trip uses a
cheap classical suite; a single PQC keygen asserts the v6/64-hex + PQC-detect
invariants. TODO stubs are asserted to raise `PgpError`.
"""

import pytest

sk_pgp = pytest.importorskip("sk_pgp")


def test_classical_sign_verify_roundtrip():
    key = sk_pgp.Key.generate("Test <t@example.com>", "cv25519", profile="rfc4880")
    sig = key.sign_detached(b"hello world")
    cert = key.cert
    assert cert.verify_detached(sig, b"hello world") is True
    assert cert.verify_detached(sig, b"tampered") is False  # never raises
    assert cert.is_post_quantum is False
    assert len(cert.fingerprint) == 40  # v4 (rfc4880)
    assert cert.fingerprint == cert.fingerprint.upper()
    assert " " not in cert.fingerprint
    assert cert.has_secret_key is False  # public half


def test_protected_key_requires_password():
    key = sk_pgp.Key.generate("Pw <p@example.com>", "cv25519", password="hunter2")
    assert key.is_protected is True
    with pytest.raises(sk_pgp.PgpError):
        key.sign_detached(b"x")  # no password
    sig = key.sign_detached(b"x", password="hunter2")
    assert key.cert.verify_detached(sig, b"x") is True


@pytest.mark.slow
def test_pqc_v6_keygen():
    key = sk_pgp.Key.generate("PQ <pq@example.com>", "mldsa87-ed448")
    assert key.is_post_quantum is True
    assert len(key.fingerprint) == 64  # v6 / RFC 9580
    sig = key.sign_detached(b"pq")
    assert key.cert.verify_detached(sig, b"pq") is True


def test_armor_roundtrip():
    key = sk_pgp.Key.generate("A <a@example.com>", "cv25519")
    pub = sk_pgp.Cert.from_armor(key.cert.to_armor())
    assert pub.fingerprint == key.fingerprint


def test_bad_armor_raises():
    with pytest.raises(sk_pgp.PgpError):
        sk_pgp.Cert.from_bytes(b"not a pgp key")


def test_no_skeleton_stubs_remain():
    """The whole binding surface is real-bound — nothing returns the skeleton
    TODO marker any more. A method may still raise PgpError for a *real* reason
    (e.g. asking for RSA numbers on an Ed25519 key), but never the stub text.
    """
    key = sk_pgp.Key.generate("S <s@example.com>", "cv25519")
    surface = [
        lambda: key.add_pqc_subkeys(),
        lambda: key.cert.rsa_public_numbers(),
        lambda: key.cert.ed25519_public_bytes(),
        lambda: key.sign_inline(b"x"),
        lambda: key.cert.verify_inline(key.sign_inline(b"x")),
        lambda: key.cert.encrypt(b"x"),
    ]
    for call in surface:
        try:
            call()
        except sk_pgp.PgpError as exc:  # a real error is fine; the stub text is not
            assert "not implemented yet (skeleton TODO)" not in str(exc), exc
