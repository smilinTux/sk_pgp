#!/usr/bin/env bash
# Build a self-contained sk_pgp wheel (brew OpenSSL 3.6.2 PQC bundled under a
# private SONAME via auditwheel — enabled by the rpath in .cargo/config.toml)
# and install it into ~/.skenv. Works in mixed-OpenSSL processes.
set -euo pipefail
source "$HOME/.cargo/env"
cd "$HOME/clawd/skcapstone-repos/sk_pgp"

# The PQC provider: the only OpenSSL with ML-DSA/ML-KEM (matches sq 1.4.0-pqc.1).
export OPENSSL_DIR="${OPENSSL_DIR:-/home/linuxbrew/.linuxbrew/opt/openssl@3}"
# auditwheel's repair pass must be able to RESOLVE brew's libcrypto.so.3 to copy
# it into the wheel — .cargo/config.toml bakes the rpath for runtime, but the
# repair scan needs it on LD_LIBRARY_PATH too.
export LD_LIBRARY_PATH="${OPENSSL_DIR}/lib:${LD_LIBRARY_PATH:-}"
export BINDGEN_EXTRA_CLANG_ARGS="-I${OPENSSL_DIR}/include ${BINDGEN_EXTRA_CLANG_ARGS:-}"

# Clean prior artifacts: a stale target/maturin/ repair dir can leave the ext
# pre-patched to the private SONAME, which then "could not be located".
rm -rf target/maturin
rm -f target/wheels/*.whl

~/.skenv/bin/maturin build --release --interpreter ~/.skenv/bin/python
WHL=$(ls -t target/wheels/sk_pgp-*.whl | head -1)
~/.skenv/bin/pip install --no-deps --force-reinstall "$WHL"

# Mixed-OpenSSL smoke: load the system libcrypto (via hashlib/ssl) FIRST, then
# sk_pgp + a real PQC sign/verify. Proves no SONAME collision.
~/.skenv/bin/python - <<'PY'
import hashlib, ssl  # noqa: F401  (force the system libcrypto to load first)
hashlib.sha256(b"x")
import sk_pgp
k = sk_pgp.Key.generate("BuildSmoke <smoke@skworld.io>", "mldsa87-ed448", password="pw")
sig = k.sign_detached(b"build-smoke", password="pw")
assert k.cert.verify_detached(sig, b"build-smoke") is True
print(f"sk_pgp {sk_pgp.__version__} installed + self-contained PQC sign/verify ✅")
PY
echo "wheel: $WHL"
