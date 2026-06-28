#!/usr/bin/env python3
"""Runnable example: v6 / RFC 9580 post-quantum keygen → sign → verify with sk_pgp.

Generates a **ML-DSA-87 + Ed448** (NIST L5) OpenPGP v6 keypair — a hybrid composite
signing identity PGPy and `gpg` 2.4 cannot produce — then signs a message and verifies
the detached signature.

Honest claim: ML-DSA / ML-KEM are **post-quantum / quantum-resistant**, NOT
"quantum-proof." The composite signature is valid **iff BOTH legs** (lattice ML-DSA
per FIPS 204 **and** classical Ed448 per RFC 8032) verify — sequoia enforces the AND,
sk_pgp only binds it. See FIPS 203/204, RFC 8032, RFC 9580, draft-ietf-openpgp-pqc.

Run:
    ./build.sh                 # build + install the self-contained wheel first
    python examples/pqc_v6_sign_verify.py
"""

import sys

import sk_pgp

USERID = "Lumina <lumina@skworld.io>"
PASSPHRASE = "correct-horse-battery-staple"
MESSAGE = b"sovereign post-quantum identity proof"


def main() -> int:
    print(f"sk_pgp {sk_pgp.__version__}\n")

    # 1) Generate a v6/RFC9580 PQC keypair (ML-DSA-87 + Ed448, NIST L5), protected.
    print(f"[1] generating {sk_pgp.CIPHER_MLDSA87_ED448} v6 key for {USERID!r} ...")
    key = sk_pgp.Key.generate(USERID, "mldsa87-ed448", password=PASSPHRASE)
    cert = key.cert  # public half

    assert cert.is_post_quantum is True, "expected a post-quantum cert"
    assert len(cert.fingerprint) == 64, "v6/RFC9580 fingerprint must be 64 hex chars"
    assert key.is_protected is True, "secret material should be passphrase-wrapped"
    print(f"    fingerprint   : {cert.fingerprint}")
    print(f"    post-quantum  : {cert.is_post_quantum}")
    print(f"    protected     : {key.is_protected}")

    # 2) Sign (composite ML-DSA + Ed448; both legs signed transparently).
    print("\n[2] signing (detached, armored) ...")
    sig = key.sign_detached(MESSAGE, password=PASSPHRASE)
    print("    " + sig.decode("utf-8", "replace").splitlines()[0])

    # 3) Verify — valid iff BOTH composite legs verify; returns a bool, never raises
    #    on a merely-wrong signature.
    print("\n[3] verifying ...")
    ok_good = cert.verify_detached(sig, MESSAGE)
    ok_tampered = cert.verify_detached(sig, MESSAGE + b"!")  # should be False
    print(f"    verify(correct data)  : {ok_good}")
    print(f"    verify(tampered data) : {ok_tampered}")

    # 4) Public cert round-trips through ASCII armor unchanged.
    reparsed = sk_pgp.Cert.from_armor(cert.to_armor())
    assert reparsed.fingerprint == cert.fingerprint

    if ok_good and not ok_tampered:
        print("\n✅ PQC v6 keygen → sign → verify round-trip OK "
              "(composite AND-semantics holds).")
        return 0
    print("\n❌ unexpected verification result", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
