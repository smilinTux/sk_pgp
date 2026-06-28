# sk_pgp examples

Runnable, self-checking examples for `sk_pgp`. Build + install the wheel first
(`./build.sh` from the repo root), then run any script with the venv interpreter.

| Script | What it shows | Speed |
|---|---|---|
| [`pqc_v6_sign_verify.py`](pqc_v6_sign_verify.py) | **The headline path:** v6/RFC 9580 **ML-DSA-87 + Ed448** (NIST L5) keygen → detached sign → verify, incl. the composite **both-legs-must-verify** semantics and a tamper check. | slow (PQC keygen) |
| [`classical_quickstart.py`](classical_quickstart.py) | Same API on a cheap classical Cv25519 v4 key — fast install smoke test. | fast |

```bash
./build.sh                                  # build + install the self-contained wheel
~/.skenv/bin/python examples/pqc_v6_sign_verify.py
~/.skenv/bin/python examples/classical_quickstart.py
```

> **Honest claim:** ML-DSA / ML-KEM are **post-quantum / quantum-resistant**, never
> "quantum-proof." A hybrid composite signature is valid **iff both** the lattice
> (ML-DSA, FIPS 204) **and** classical (Ed448, RFC 8032) legs verify. sk_pgp binds
> sequoia + OpenSSL + liboqs and adds no original cryptography.
