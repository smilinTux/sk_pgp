#!/usr/bin/env python3
"""Fast quickstart: classical Cv25519 v4 keygen → sign → verify (no slow PQC keygen).

Same API surface as the PQC example, but using a cheap classical suite so it runs in
well under a second — handy for smoke-testing an install. For the real post-quantum
(ML-DSA-87 + Ed448, v6) path see ``pqc_v6_sign_verify.py``.

Run:
    python examples/classical_quickstart.py
"""

import sk_pgp


def main() -> int:
    print(f"sk_pgp {sk_pgp.__version__}")

    key = sk_pgp.Key.generate("Alice <alice@example.com>", "cv25519", profile="rfc4880")
    cert = key.cert

    sig = key.sign_detached(b"hello world")
    assert cert.verify_detached(sig, b"hello world") is True
    assert cert.verify_detached(sig, b"goodbye world") is False  # never raises
    assert cert.is_post_quantum is False
    assert len(cert.fingerprint) == 40  # v4 / RFC 4880

    print(f"fingerprint (v4) : {cert.fingerprint}")
    print("✅ classical sign/verify round-trip OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
