#!/usr/bin/env bash
set -uo pipefail
source "$HOME/.cargo/env"
OSSL=/home/linuxbrew/.linuxbrew/opt/openssl@3
export OPENSSL_DIR="$OSSL" OPENSSL_LIB_DIR="$OSSL/lib" OPENSSL_INCLUDE_DIR="$OSSL/include"
export PKG_CONFIG_PATH="$OSSL/lib/pkgconfig" BINDGEN_EXTRA_CLANG_ARGS="-I$OSSL/include"
export C_INCLUDE_PATH="$OSSL/include" CARGO_BUILD_JOBS=2
cd "$HOME/clawd/skcapstone-repos/sk_pgp"
echo "=== maturin develop @ $(date) (rustc $(rustc --version)) ==="
~/.skenv/bin/maturin develop --release 2>&1
echo "=== exit=$? @ $(date) ==="
