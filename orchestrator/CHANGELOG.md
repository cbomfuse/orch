# Changelog

## Unreleased

- New built-in tool `cbomkit-theia` (CBOMkit-theia, the CBOMkit scanner for directories and container
  images), enabled by default as the fourth generator: `ghcr.io/cbomkit/cbomkit-theia:<version>` with
  `dir`, or `--launcher local` via `go install`.  Exported to 2CBOM as `static-binary`, matching its
  knowledge base.
- Tool specs: `capture_stdout: true` saves a tool's stdout as its output (`run_command` and
  `Docker.run` gained `stdout_path`); a tool that exits 0 without printing anything is `failed`.
- Tool specs: `"*"` under `languages` runs a language-agnostic tool on every case, including
  languages added to the baseline later.
- A run that times out with truncated output keeps the status `timeout`.
- New built-in tool `cryptoscan` (CSNP CryptoScan), enabled by default as the fifth generator: built with
  `go install` and run as `scan --format cbom --include-quantum-safe --no-config`; exported to 2CBOM as
  `static-source`.
- Tool specs: `ok_exit_codes` lists the exit codes that mean success (CryptoScan exits 1 on a CRITICAL
  finding), so such runs carry no "exited with 1" note.
- `--launcher` / `tools.default_launcher` switches only the tools that define that launcher; a
  Docker-only tool (`cbomkit`) or a local-only one (`cryptoscan`) keeps its own.
- Lexicon: `SHAKE` without a size is SHA-3 (XOF), and `ECC` is the generic elliptic-curve family, like `EC`.
- New built-in tool `cbom-lens` (OmniTrust CBOM-Lens), enabled by default as the sixth generator: built
  with `go build` from a shallow checkout of the release commit (its `go.mod` has `exclude` directives,
  which `go install module@version` rejects), run as `run --config` on a config written per run that
  names the case workspace, CBOM 1.6 from stdout; exported to 2CBOM as `static-binary`.
- Tool specs: `files:` writes config files (placeholders rendered) to `{files}` before each run.
- The self-reported tool comes from `metadata.component` when `metadata.tools` is empty and the
  component's name is one of the tool's aliases (CBOM-Lens identifies itself that way).
- Scoring model 1.1, for the baseline's new `Artifacts` case (certificates, keys, keystores, secrets
  and a TLS configuration as files):
  - Ground-truth occurrences marked `fileLevel` are hit by a location that names the file, with or
    without a line; locality counts the places (PEM blocks, keystore entries) an asset is stored.
  - On file-level hits only the best-scoring candidates receive a detection (a certificate file holds
    an RSA key and an RSA signature), and a detection that points into an artifact file holding no
    compatible asset is a false positive unless it is an implicit asset.
  - Certificates are matched by identity (subject, issuer, validity) instead of "the" certificate;
    subject and issuer names are compared order- and spelling-insensitively (a common name alone
    earns its share of the name's attributes), validity times as instants
    (`orchestrator.normalize.x509`).
  - An OID several assets share (`rsaEncryption`, `id-ecPublicKey`) no longer overrides a conflicting
    key size; `other` material matches `other` (CSR, CRL); a secret a scanner mistyped (`key` for a
    password) counts where it is located.
  - Non-asset mentions may name their file; the certificate's `signatureAlgorithmRef` is scored with
    the referenced component's properties.
  - The oracle declares `Artifacts`; reports show "files" as the program of an artifact case.
  Re-scoring stored outputs for the five program cases reproduces the 1.0 ledger for every tool
  whose certificate findings name the corpus certificate or nothing.

## 0.1.0 — 2026-11-05

Initial release.

- Baseline sync and automatic case discovery (`cbomfuse/baseline`).
- Generic YAML tool adapters (Docker or local), newest-release resolution with commit/digest recording.
- Built-in tools: CBOMkit (cbomkit-action image), cdxgen, cryptobom-forge (with CodeQL bundle pipeline),
  plus `oracle`/`oracle-noisy` for self-tests.
- Normalisers for CycloneDX 1.5/1.6/1.7 and IBM 1.4-cbom-1.0.
- Matching (OID → descriptor slots → source location), attribute scoring, lexical false positives.
- Category scorecard, pairwise head-to-head statistics, Bayesian reconciliation API with backoff.
- Exports: `scorecard.json`, `priors.json`, `report.md`, 2CBOM `tools.json`.
