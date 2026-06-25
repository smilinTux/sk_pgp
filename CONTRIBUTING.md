# Contributing to sk_pgp

Thanks for helping build the sovereign post-quantum OpenPGP library for Python.
sk_pgp is a **crypto component** — contributions are held to the SK
**CRYPTOGRAPHY_STANDARD** honest-claims bar and the **SK_REPO_DOC_STANDARD** doc bar.
Read [SOP.md](SOP.md) and [SECURITY.md](SECURITY.md) before your first change.

---

## Ground rules (non-negotiable)

1. **We bind vetted crypto; we never hand-roll it.** Every primitive must flow through
   `sequoia-openpgp` → `crypto-openssl` (OpenSSL 3.6.2) → liboqs. PRs that introduce
   original cryptographic code, or a new unaudited primitive, will be rejected.
2. **Honest claims only.** In code, docstrings, README, CHANGELOG, and PR text: use
   **"post-quantum" / "quantum-resistant,"** never "quantum-proof," "quantum-safe,"
   "unbreakable," "CNSA 2.0 compliant," or "FIPS 206/Falcon." Never imply AES-256 is
   quantum-broken. Scope every claim to its **surface** (signing vs. KEM) and cite the
   FIPS number (203/204/205) + hybrid-vs-classical.
3. **"PQC" ≠ encryption here.** sk_pgp is a **signing** engine; KEM encrypt/decrypt is
   TODO. Do not describe sk_pgp as HNDL-resistant or as "post-quantum encryption."
4. **No claim without evidence.** A capability/security statement must be backed by a
   test, a self-report (`is_post_quantum`, fingerprint length), or a cited spec. If
   you can't show it, soften or delete it (SOP §9 honest-claims gate).
5. **No secrets in the tree.** Never commit a live private key, passphrase, or token.
   Generate test keys on the fly; use only dedicated non-production fixtures.

---

## Branch model

- `main` is the protected default; never commit directly to it.
- Branch per change: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`, `chore/<slug>`.
- Crypto-migration work tracks the ecosystem epic `PQC-MIGRATION` (coord `e1d6ba2a`).
- Keep PRs focused; one logical change per PR.

## Commit convention

- Imperative subject, explain the *why* in the body.
- **Every commit ends with the trailer:**
  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  ```
- Reference issues/epics where relevant. Do **not** commit or push unless the change
  is requested/expected; if you are on `main`, branch first.

---

## Development setup

```bash
source ~/.cargo/env                                          # rustc 1.96.0 (floor 1.85)
# .cargo/config.toml sets OPENSSL_DIR + PKG_CONFIG_PATH + the brew-openssl rpath.
# liboqs 0.14 at ~/.local/lib/liboqs.so must be on the linker/runtime path.

# Fast inner loop (NOTE: collides in mixed-OpenSSL processes — unit work only):
~/.skenv/bin/maturin develop --release

# The CORRECT build for anything touching import/packaging — self-contained wheel:
./build.sh        # maturin build --release → bundled wheel → pip install → import smoke
```

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for the OpenSSL SONAME collision and why
`./build.sh` (not `maturin develop`) is the validation path.

---

## Test gate (must be green before review)

```bash
~/.skenv/bin/python -m pytest tests/ -v               # full suite
~/.skenv/bin/python -m pytest tests/ -v -m "not slow" # fast (skips PQC keygen)
```

A change is **not reviewable** until:

- [ ] `pytest tests/` is green (including at least one `slow` PQC keygen run on a
      build host).
- [ ] The **mixed-OpenSSL import test** passes — load system `libcrypto` first, then
      `import sk_pgp` and generate/sign/verify (SOP §3.2 / §5.1).
- [ ] New behavior has a test. New TODO stubs raise `PgpError` and are asserted in
      `test_todo_stubs_raise` (guards against silent wrong answers).
- [ ] Public API changes are reflected in `SOP.md §7`, `README.md`, and `CHANGELOG.md`.
- [ ] `Cargo.lock` changes are intentional; the `sequoia-openpgp =2.2.0-pqc.1`
      `crypto-openssl` pin is intact (a non-PQC resolve is a blocker).

When you implement a TODO surface (e.g. `Cert.encrypt` / `Key.decrypt`), you must:
move it out of `test_todo_stubs_raise`, add real round-trip + cross-impl vectors,
update the maturity tier in SOP §9 (e.g. KEM lands → T2), and update the honest-claims
language (KEM unlocks the HNDL discussion — scope it correctly).

---

## Review path

1. Open a PR from your branch into `main` with the per-repo compliance checklist
   (below) filled in.
2. At least one maintainer reviews. Crypto-surface or claim-language changes require
   maintainer (Chef / smilinTux) sign-off.
3. CI / local gate green (tests + mixed-OpenSSL import).
4. Squash-or-merge per maintainer preference; ensure the `Co-Authored-By` trailer
   survives.

### PR compliance checklist (paste into the PR)

```
Doc/claim gate
[ ] No forbidden crypto words; claims surface-scoped + FIPS-cited + hybrid-vs-classical
[ ] "PQC" not used to imply encryption; AES-256 not called broken
[ ] Maturity tier in SOP §9 still accurate (T3-capable signing; T2/KEM TODO)
[ ] README/SOP/CHANGELOG updated for any API or claim change

Test gate
[ ] pytest tests/ green (incl. one slow PQC keygen)
[ ] mixed-OpenSSL import test passes (./build.sh path)
[ ] new TODO stubs raise PgpError and are asserted

Crypto integrity
[ ] No hand-rolled crypto; only sequoia/openssl/liboqs primitives
[ ] sequoia =2.2.0-pqc.1 crypto-openssl pin intact; Cargo.lock drift intentional
[ ] No secrets committed
```

---

## Reporting security issues

Do **not** use a PR or public issue. Follow [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under **Apache-2.0**
([LICENSE](LICENSE)).
