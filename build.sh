#!/usr/bin/env bash
# Build a self-contained sk_pgp wheel (brew OpenSSL 3.6.2 PQC bundled under a
# private SONAME via auditwheel — enabled by the rpath in .cargo/config.toml)
# and install it into ~/.skenv. Works in mixed-OpenSSL processes.
set -euo pipefail
source "$HOME/.cargo/env"
cd "$HOME/clawd/skcapstone-repos/sk_pgp"
rm -f target/wheels/*.whl
~/.skenv/bin/maturin build --release --interpreter ~/.skenv/bin/python
WHL=$(ls -t target/wheels/sk_pgp-*.whl | head -1)
~/.skenv/bin/pip install --no-deps --force-reinstall "$WHL"
~/.skenv/bin/python -c "import sk_pgp; print('sk_pgp', sk_pgp.__version__, 'installed + importable ✅')"
