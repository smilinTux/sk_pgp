#!/usr/bin/env bash
# Verify that the OpenSSL libcrypto.so.3 about to be bundled into the sk_pgp wheel
# matches the pinned version + sha256 (scripts/openssl-pin.env). This is the
# supply-chain / reproducibility gate for the self-contained wheel build: a silent
# brew `openssl@3` upgrade would otherwise swap the bundled crypto library with no
# visible diff. On any mismatch this FAILS (non-zero) with a clear operator message.
#
# Usage:
#   verify-openssl-pin.sh [LIBCRYPTO_PATH]
#     LIBCRYPTO_PATH  optional; the libcrypto.so.3 to check. Defaults to the
#                     resolved $OPENSSL_DIR/lib/libcrypto.so.3.
# Env:
#   OPENSSL_DIR       brew openssl@3 prefix (default: linuxbrew opt/openssl@3).
#   OPENSSL_PIN_ENV   override path to the pin file (default: sibling openssl-pin.env).
#   SKIP_VERSION_CHECK=1  skip the `openssl version` check (checksum still enforced).
#
# Exit codes: 0 ok · 2 usage/setup error · 3 pin mismatch (re-pin needed).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIN_ENV="${OPENSSL_PIN_ENV:-$SCRIPT_DIR/openssl-pin.env}"
OPENSSL_DIR="${OPENSSL_DIR:-/home/linuxbrew/.linuxbrew/opt/openssl@3}"

if [[ ! -f "$PIN_ENV" ]]; then
  echo "verify-openssl-pin: FATAL: pin file not found: $PIN_ENV" >&2
  exit 2
fi
# shellcheck source=/dev/null
source "$PIN_ENV"

if [[ -z "${EXPECTED_LIBCRYPTO_SHA256:-}" ]]; then
  echo "verify-openssl-pin: FATAL: EXPECTED_LIBCRYPTO_SHA256 not set in $PIN_ENV" >&2
  exit 2
fi

# Resolve the libcrypto to check (symlink -> real file).
LIB_ARG="${1:-$OPENSSL_DIR/lib/libcrypto.so.3}"
if [[ ! -e "$LIB_ARG" ]]; then
  echo "verify-openssl-pin: FATAL: libcrypto not found: $LIB_ARG" >&2
  echo "  (is brew openssl@3 installed at OPENSSL_DIR=$OPENSSL_DIR ?)" >&2
  exit 2
fi
LIB_REAL="$(readlink -f "$LIB_ARG")"

ACTUAL_SHA256="$(sha256sum "$LIB_REAL" | awk '{print $1}')"

if [[ "$ACTUAL_SHA256" != "$EXPECTED_LIBCRYPTO_SHA256" ]]; then
  cat >&2 <<EOF
verify-openssl-pin: PIN MISMATCH. Refusing to build.

  The libcrypto.so.3 that would be bundled into the sk_pgp wheel does NOT match
  the pinned checksum. The OpenSSL library changed underneath the build (most
  likely a brew \`openssl@3\` upgrade). Building now would silently ship a
  DIFFERENT crypto library than the one that was reviewed.

  library : $LIB_REAL
  expected: $EXPECTED_LIBCRYPTO_SHA256  (${EXPECTED_OPENSSL_VERSION:-unknown version})
  actual  : $ACTUAL_SHA256

  If this change is intentional (a deliberate OpenSSL upgrade), RE-PIN on purpose:
    1. Verify the new openssl@3 is the intended PQC build (ML-DSA / ML-KEM).
    2. Update scripts/openssl-pin.env:
         EXPECTED_OPENSSL_VERSION="\$( "$OPENSSL_DIR/bin/openssl" version | cut -d' ' -f1-2 )"
         EXPECTED_LIBCRYPTO_SHA256="$ACTUAL_SHA256"
    3. Commit the re-pin as its own reviewed change.
EOF
  exit 3
fi

# Secondary, non-fatal-by-default version cross-check (checksum is the hard gate).
if [[ "${SKIP_VERSION_CHECK:-0}" != "1" && -n "${EXPECTED_OPENSSL_VERSION:-}" ]]; then
  OPENSSL_BIN="$OPENSSL_DIR/bin/openssl"
  if [[ -x "$OPENSSL_BIN" ]]; then
    ACTUAL_VERSION="$("$OPENSSL_BIN" version | cut -d' ' -f1-2)"
    if [[ "$ACTUAL_VERSION" != "$EXPECTED_OPENSSL_VERSION" ]]; then
      cat >&2 <<EOF
verify-openssl-pin: PIN MISMATCH. Refusing to build.

  \`openssl version\` does not match the pin (checksum matched, but the reported
  version disagrees; treat as a changed toolchain and re-pin intentionally).
    expected: $EXPECTED_OPENSSL_VERSION
    actual  : $ACTUAL_VERSION
EOF
      exit 3
    fi
  else
    echo "verify-openssl-pin: note: $OPENSSL_BIN not executable; skipped version cross-check" >&2
  fi
fi

echo "verify-openssl-pin: OK. Bundled libcrypto matches pin (${EXPECTED_OPENSSL_VERSION:-?}, sha256 ${EXPECTED_LIBCRYPTO_SHA256:0:12}...)"
echo "  library: $LIB_REAL"
echo "  private SONAME cross-check: libcrypto-${EXPECTED_LIBCRYPTO_SHA256:0:8}.so.3"
