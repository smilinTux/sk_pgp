"""Tests for the last real-bound surface:

  * additive PQC subkeys   -> ``Key.add_pqc_subkeys``
  * RSA JWK numbers         -> ``Cert.rsa_public_numbers``
  * Ed25519 JWK point bytes -> ``Cert.ed25519_public_bytes``

Honesty: post-quantum / quantum-resistant, never "quantum-proof". The composite
ML-DSA+EdDSA / ML-KEM+X-DH subkeys are valid iff BOTH legs hold. PQC keygen is
slow, so the heavy composite cases are marked ``@slow``; the JWK exporters and
the additive invariant use cheap classical keys where possible.
"""

import pytest

sk_pgp = pytest.importorskip("sk_pgp")


# --------------------------------------------------------------------------
# JWK exporters: Cert.rsa_public_numbers / Cert.ed25519_public_bytes
# --------------------------------------------------------------------------

def test_rsa_public_numbers():
    key = sk_pgp.Key.generate("RSA <rsa@example.com>", "rsa3k")
    n, e = key.cert.rsa_public_numbers()
    assert isinstance(n, int) and isinstance(e, int)
    assert e == 65537                      # standard public exponent
    assert n.bit_length() in (3071, 3072)  # ~3072-bit modulus (top bit may be 0)
    assert n > e


def test_rsa_public_numbers_on_non_rsa_raises():
    key = sk_pgp.Key.generate("Ed <ed@example.com>", "cv25519")
    with pytest.raises(sk_pgp.PgpError):
        key.cert.rsa_public_numbers()  # Ed25519 primary, no RSA numbers


def test_ed25519_public_bytes_v6():
    key = sk_pgp.Key.generate("Ed6 <ed6@example.com>", "cv25519")  # default rfc9580/v6
    raw = key.cert.ed25519_public_bytes()
    assert isinstance(raw, bytes)
    assert len(raw) == 32  # bare Ed25519 public point
    # Stable across re-parse of the same cert.
    again = sk_pgp.Cert.from_armor(key.cert.to_armor()).ed25519_public_bytes()
    assert again == raw


def test_ed25519_public_bytes_v4():
    key = sk_pgp.Key.generate("Ed4 <ed4@example.com>", "cv25519", profile="rfc4880")
    raw = key.cert.ed25519_public_bytes()
    assert len(raw) == 32  # 0x40 native-form prefix stripped


def test_ed25519_public_bytes_on_rsa_raises():
    key = sk_pgp.Key.generate("RSA2 <rsa2@example.com>", "rsa3k")
    with pytest.raises(sk_pgp.PgpError):
        key.cert.ed25519_public_bytes()


# --------------------------------------------------------------------------
# additive PQC subkeys: Key.add_pqc_subkeys
# --------------------------------------------------------------------------

def test_add_pqc_subkeys_is_additive_and_makes_pq():
    classical = sk_pgp.Key.generate("Add <add@example.com>", "cv25519")
    assert classical.is_post_quantum is False

    augmented = classical.add_pqc_subkeys()  # default mldsa87-ed448
    # Additive invariant: same primary => same fingerprint.
    assert augmented.fingerprint == classical.fingerprint
    # It now carries PQC material.
    assert augmented.is_post_quantum is True
    assert augmented.cert.is_post_quantum is True
    # Still a usable secret key.
    assert augmented.cert.has_secret_key is False  # .cert is the public half


def test_add_pqc_subkeys_signs_and_verifies():
    augmented = sk_pgp.Key.generate("Sg <sg@example.com>", "cv25519").add_pqc_subkeys()
    sig = augmented.sign_detached(b"after-augment")
    assert augmented.cert.verify_detached(sig, b"after-augment") is True
    assert augmented.cert.verify_detached(sig, b"tampered") is False


def test_add_pqc_subkeys_kem_roundtrip():
    # The augmented cert gains an ML-KEM encryption subkey; encrypt/decrypt must
    # still round-trip (the recipient now has both classical + PQC enc subkeys).
    augmented = sk_pgp.Key.generate("Km <km@example.com>", "cv25519").add_pqc_subkeys()
    ct = augmented.cert.encrypt(b"sealed-after-augment")
    assert augmented.decrypt(ct) == b"sealed-after-augment"


def test_add_pqc_subkeys_password_protected():
    key = sk_pgp.Key.generate("Pw <pw@example.com>", "cv25519", password="pw7")
    # Wrong/absent password to unlock the primary must fail.
    with pytest.raises(sk_pgp.PgpError):
        key.add_pqc_subkeys()
    augmented = key.add_pqc_subkeys(password="pw7")
    assert augmented.fingerprint == key.fingerprint
    assert augmented.is_post_quantum is True
    # The augmented signing path requires the same passphrase.
    with pytest.raises(sk_pgp.PgpError):
        augmented.sign_detached(b"x")
    sig = augmented.sign_detached(b"x", password="pw7")
    assert augmented.cert.verify_detached(sig, b"x") is True


def test_add_pqc_subkeys_l3_suite():
    augmented = sk_pgp.Key.generate("L3 <l3@example.com>", "cv25519").add_pqc_subkeys(
        cipher_suite="mldsa65-ed25519"
    )
    assert augmented.fingerprint == augmented.fingerprint
    assert augmented.is_post_quantum is True


def test_add_pqc_subkeys_unknown_suite_raises():
    key = sk_pgp.Key.generate("Bad <bad@example.com>", "cv25519")
    with pytest.raises(sk_pgp.PgpError):
        key.add_pqc_subkeys(cipher_suite="bogus-suite")


def test_add_pqc_subkeys_rejects_v4_primary():
    # PQC subkeys are invalid on a v4 primary; sequoia must reject the mix.
    key = sk_pgp.Key.generate("V4 <v4@example.com>", "cv25519", profile="rfc4880")
    with pytest.raises(sk_pgp.PgpError):
        key.add_pqc_subkeys()


@pytest.mark.slow
def test_add_pqc_subkeys_onto_pqc_primary():
    # Augmenting an already-PQC (v6) key is still additive.
    pq = sk_pgp.Key.generate("PQ <pq@example.com>", "mldsa87-ed448")
    augmented = pq.add_pqc_subkeys()
    assert augmented.fingerprint == pq.fingerprint
    assert augmented.is_post_quantum is True
