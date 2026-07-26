"""Supply-chain gate test: scripts/verify-openssl-pin.sh must ACCEPT the pinned
libcrypto and REJECT (exit 3) a different/tampered one.

The verify script is the gate build.sh runs before auditwheel bundles brew's
libcrypto.so.3 into the self-contained wheel (KNOWN_ISSUES.md section 1). These
tests drive it with a controlled fixture + a controlled pin file so they do not
depend on brew being installed, plus one guard that the checked-in pin value
actually matches the real bundled library when it is present.
"""
import hashlib
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VERIFY = REPO / "scripts" / "verify-openssl-pin.sh"
PIN_ENV = REPO / "scripts" / "openssl-pin.env"


def _run(lib_path, pin_env, extra_env=None):
    env = dict(os.environ)
    env["OPENSSL_PIN_ENV"] = str(pin_env)
    env["SKIP_VERSION_CHECK"] = "1"  # checksum is the hard gate; isolate it here
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(VERIFY), str(lib_path)],
        capture_output=True, text=True, env=env,
    )


def _write_pin(tmp_path, sha256, version="OpenSSL 3.6.2"):
    p = tmp_path / "pin.env"
    p.write_text(
        f'EXPECTED_OPENSSL_VERSION="{version}"\n'
        f'EXPECTED_LIBCRYPTO_SHA256="{sha256}"\n'
    )
    return p


def test_verify_script_exists_and_executable():
    assert VERIFY.exists(), "verify-openssl-pin.sh missing"
    assert os.access(VERIFY, os.X_OK), "verify-openssl-pin.sh not executable"
    assert PIN_ENV.exists(), "openssl-pin.env missing"


def test_pass_when_checksum_matches(tmp_path):
    fixture = tmp_path / "libcrypto.so.3"
    fixture.write_bytes(b"pretend-this-is-libcrypto-\x00\x01\x02" * 100)
    good = hashlib.sha256(fixture.read_bytes()).hexdigest()
    pin = _write_pin(tmp_path, good)

    r = _run(fixture, pin)
    assert r.returncode == 0, f"expected pass, got {r.returncode}: {r.stderr}"
    assert "OK" in r.stdout


def test_fail_when_checksum_differs(tmp_path):
    fixture = tmp_path / "libcrypto.so.3"
    fixture.write_bytes(b"pretend-this-is-libcrypto-\x00\x01\x02" * 100)
    # Pin to a DIFFERENT sha (simulates a silent brew openssl@3 upgrade).
    wrong = "0" * 64
    pin = _write_pin(tmp_path, wrong)

    r = _run(fixture, pin)
    assert r.returncode == 3, f"expected exit 3 (mismatch), got {r.returncode}: {r.stdout}{r.stderr}"
    assert "PIN MISMATCH" in r.stderr
    assert "re-pin" in r.stderr.lower()


def test_fail_when_lib_tampered(tmp_path):
    # Pin to the ORIGINAL bytes, then tamper the file -> must be rejected.
    fixture = tmp_path / "libcrypto.so.3"
    original = b"original-crypto-bytes" * 200
    fixture.write_bytes(original)
    pin = _write_pin(tmp_path, hashlib.sha256(original).hexdigest())
    # tamper (append one byte -> different sha)
    fixture.write_bytes(original + b"\xff")

    r = _run(fixture, pin)
    assert r.returncode == 3, f"expected exit 3 for tampered lib, got {r.returncode}"
    assert "PIN MISMATCH" in r.stderr


def test_checked_in_pin_matches_real_lib_if_present():
    """Guard the actual committed pin value: if the real brew libcrypto.so.3 is
    present it MUST match the checked-in sha256 (else the pin is stale)."""
    openssl_dir = os.environ.get(
        "OPENSSL_DIR", "/home/linuxbrew/.linuxbrew/opt/openssl@3"
    )
    lib = Path(openssl_dir) / "lib" / "libcrypto.so.3"
    if not lib.exists():
        import pytest
        pytest.skip(f"brew libcrypto not present at {lib}")

    r = subprocess.run(
        ["bash", str(VERIFY)],
        capture_output=True, text=True,
        env={**os.environ, "OPENSSL_DIR": openssl_dir},
    )
    assert r.returncode == 0, (
        "checked-in openssl-pin.env does not match the installed libcrypto. "
        f"re-pin intentionally.\n{r.stdout}\n{r.stderr}"
    )
