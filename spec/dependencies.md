# Security dependencies

The structural language remains standard-library-only. The security gate needs
Ed25519 verification, which neither Python nor Rust standard libraries supply.
Implementing signature arithmetic ourselves would violate DESIGN.md.

- Python `PyNaCl==1.6.2`: PyCA bindings to libsodium, using Ed25519 signing,
  verification and validated point checks. Apache-2.0 (bundled libsodium: ISC).
  Reject weak/noncanonical points using the library, never homemade curve code.
  Its CFFI/pycparser dependencies are locked in the local virtual environment.
- Rust `ed25519-dalek`: established Ed25519 implementation; strict verification,
  reject weak public keys. BSD-3-Clause. No batch/hazmat verification APIs.
- Rust `sha2`: established SHA-256 implementation for exact action binding;
  MIT OR Apache-2.0. No custom hashing.
- Rust `serde`/`serde_json`: typed signed claims, deny unknown fields and duplicate
  struct fields; MIT OR Apache-2.0. Exact signed bytes are verified before claims
  become trusted. Explicit size limits precede decoding.

Pin Python's resolved environment and Rust's Cargo.lock. Review transitive
updates and advisories before releases. The license choices above describe
dependencies, not a license grant for this repository. No repository LICENSE
is selected implicitly. Signing keys must never be committed, logged or sent
to tests; tests use generated ephemeral keys or public deterministic test vectors.

References: https://pynacl.readthedocs.io/en/latest/signing/
and https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html.

Development tooling: mypy is pinned in the dev dependency group and checks all
Python runtime packages with `--strict`. It is not a runtime dependency. On
2026-11-15, pip-audit on the locked runtime requirements and cargo-audit on
`rust/Cargo.lock` reported no known vulnerabilities. This is an advisory snapshot,
not a guarantee; repeat the checks for releases and dependency updates.

The build backend is pinned Hatchling 1.33.0 (PyPA, MIT). It creates standard
wheel/sdist artifacts; Python's standard library has no packaging backend.
It is build-only, not a deployed runtime dependency. Its packaging, pathspec,
pluggy and trove-classifiers dependencies are build tooling. Artifact checks
exclude caches, local configuration and secrets; no custom build hooks run.

CI pins checkout v4.4.0 and setup-python v5.6.0 to their full upstream Git commit
IDs in `.github/workflows/verify.yml`, verified against the upstream release tags.
Rust is pinned to the locally tested 1.96.0 toolchain, including Clippy, rather
than a floating stable channel. Python's 3.12 patch releases and the hosted
Ubuntu image still receive upstream updates.

CI also checks the locked runtime dependencies with pip-audit 2.10.1 and
cargo-audit 0.22.0. Python requirements are exported from `uv.lock` without dev
packages or the local project, with package hashes; the audit disables package
installation and dependency resolution. Cargo-audit is installed with its
published lockfile into a temporary job directory, not the runtime environment.
Both tools are build-only and their versions match the locally verified tools.
Their advisory databases are fetched fresh: new advisories and unavailable
feeds can fail CI, and are not suppressed. Tool installation transitive packages
are not all independently pinned here (cargo-audit uses its published lockfile);
review upgrades rather than assuming these pins eliminate supply-chain risk.
Hosted CI execution remains a separate check from local command verification.
