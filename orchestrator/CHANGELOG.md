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
