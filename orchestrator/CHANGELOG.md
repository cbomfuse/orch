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
