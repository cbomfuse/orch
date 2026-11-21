# Running the benchmark

## Requirements

| Component | Needed for | Notes |
|---|---|---|
| Python ≥ 3.10, `git` | everything | `pip install -e .` installs the only dependency (PyYAML) |
| Docker (or Podman with a `docker` shim) | `cbomkit`, `cdxgen`, `cbomkit-theia` (default launcher) | images are pulled by release tag; set `docker.pull_policy` |
| Node.js ≥ 24 | `cdxgen` with `--launcher local` | installed into `.orchestrator/cache/cdxgen` via npm |
| Go ≥ 1.21 | `cryptoscan`, `cbom-lens` (their only launcher); `cbomkit-theia` with `--launcher local` | built into `.orchestrator/cache/<tool>/<version>` (`go install`; cbom-lens with `go build` from a checkout); `GOTOOLCHAIN=auto` fetches the Go release a tool's `go.mod` requires (1.26.9 for cbom-lens 1.1.1) |
| ~1 GB disk, Python venv | `cryptobom-forge` | the CodeQL bundle (CLI + query packs) is downloaded once into `.orchestrator/cache/cryptobom-forge/codeql/<version>` |
| `GITHUB_TOKEN` (optional) | version resolution | lifts the unauthenticated API limit; without it `git ls-remote` is used, which needs no token |

CBOMkit has no local launcher: its jar depends on packages published on GitHub Packages, so the
release image is the reproducible artefact.

## Commands

```bash
orchestrator init                     # write orchestrator.yaml + tools.d/
orchestrator baseline sync|cases|info
orchestrator tools list|show <tool>|resolve [tool…]|install [tool…] [--pin tool=version] [--launcher …]
orchestrator run [--tool T]… [--case C]… [--pin tool=version]… [--launcher docker|local]
                 [--offline] [--skip-install] [--run-id ID] [--fail-fast] [--no-evaluate]
                 [--baseline-ref REF] [--baseline-repo URL|PATH]
orchestrator evaluate <run> [--baseline PATH]     # (re)score raw outputs; e.g. after a baseline update
orchestrator report <run> [--format md|json]
orchestrator export twocbom|priors <run> [--out FILE] [--tool T]…
orchestrator reconcile <run> --tool-a A --tool-b B [--category "k=v;k=v"] [--attribute NAME]
                       [--value-a V] [--value-b V] [--json]
orchestrator runs list | runs diff <run1> <run2>
orchestrator normalize <cbom.json> [--verbose]     # see how a file is lifted to the detection model
```

`<run>` is a run id, a run directory, or a `scorecard.json`/`priors.json` path.  `--launcher` switches
only the tools that define that launcher: `cbomkit` stays on Docker, `cryptoscan` and `cbom-lens` stay local.

## Typical sessions

Newest versions of everything, nightly:

```bash
orchestrator -v run            # resolves, pulls/installs, scans 5 cases × 6 tools, evaluates, exports
```

Reproduce a previous run's versions:

```bash
jq '.tools | map_values(.tag // .version)' results/20261105-213000/manifest.json
orchestrator run --pin cbomkit=v2.3.0 --pin cdxgen=v13.6.0 --pin cryptobom-forge=1.1.0 --pin codeql=codeql-bundle-v2.27.4 \
                 --pin cbomkit-theia=v1.1.2 --pin cryptoscan=v1.5.0 --pin cbom-lens=1.1.1
```

The baseline changed (new scenario, corrected ground truth): re-score without re-running tools:

```bash
orchestrator baseline sync
orchestrator evaluate 20261105-213000 --baseline .orchestrator/baseline
```

Only one tool, only Java, keep the workspaces for debugging:

```bash
orchestrator run --tool cbomkit --case Java --run-id cbomkit-java --skip-install   # with results.keep_workspaces: true
```

## How each built-in tool is run

* **cbomkit** — `ghcr.io/cbomkit/cbomkit-action:<version>` with `GITHUB_WORKSPACE=/github/workspace`
  (the case copy), `CBOMKIT_LANGUAGES=<java|python|go|csharp>`, `CBOMKIT_JAVA_REQUIRE_BUILD=false`,
  `CBOMKIT_OUTPUT_DIR=/github/workspace/cbom`; output `cbom/cbom.json`.  TypeScript is not supported
  by the Sonar Cryptography plugin and is recorded as `unsupported`.
* **cdxgen** — `ghcr.io/cyclonedx/cdxgen:<tag>` with
  `-t <python|java|go|js|dotnet> --include-crypto --evidence --deep --spec-version 1.6` (what the
  `cbom` alias sets, pinned to the 1.6 schema so `cryptographic-asset` components validate against
  the corpus' spec version); output `cbom.cdxgen.json`.
* **cryptobom-forge** — CodeQL bundle (CLI + query packs) → `codeql database create`
  (`--build-mode=none` for Java/C#) → `codeql database analyze` with the cryptography inventory
  queries (`experimental/cryptography/inventory/new_models` for Python,
  `experimental/quantum/InventorySlices` for Java; other languages have no inventory queries in the
  CodeQL repository and are `unsupported` until you add a `queries:` entry) → `cryptobom generate`.
  The forge is installed into a venv from its GitHub tag; its CycloneDX fork is installed over HTTPS
  because the forge's own metadata pins it with a `git+ssh` URL.
* **cbomkit-theia** — `ghcr.io/cbomkit/cbomkit-theia:<version>` (entrypoint `cbomkit-theia`) with
  `dir /src`, `--network none` and `HOME=/tmp`; theia prints the CBOM on stdout, which is saved as
  `cbom.theia.json` (`capture_stdout`).  It scans files, not source code — certificates, keys and
  other secrets (gitleaks rules), OpenSSL TLS configuration — so it runs on every case whatever the
  language, and on the current source-only corpus it can only find embedded key material and credentials.
  Its java.security plugin only re-scores a CBOM given with `--bom` and stays inactive.  CBOMs from the
  image report version `edge`; the manifest's image digest and OCI version label identify the build.
  `--launcher local` builds the release with `go install` (v1.1.0 or later).
* **cryptoscan** — built with `go install github.com/csnp/cryptoscan/cmd/cryptoscan@<commit>` (no
  image is published) with the release binaries' version flag, then
  `cryptoscan scan <case> --format cbom --include-quantum-safe --no-config --output cbom.cryptoscan.json`.
  `--include-quantum-safe` puts back the SHA-2 and AES findings CryptoScan leaves out by default; the
  `cbom` command runs the same scan without them and has no such flag.  `scan` exits 1 when a finding
  is CRITICAL, which `ok_exit_codes: [0, 1]` treats as success.  It is pattern-based and runs on every
  case.  Release 1.5.0 writes TLS findings as `algorithm` components rather than `protocol`, so its
  protocol recall is 0 until a release carries the fix already on its main branch.
* **cbom-lens** — no image is published, and `go install …@<commit>` refuses the module because its
  `go.mod` excludes dependency versions with known CVEs (`go install` rejects `exclude` and `replace`
  directives).  The release is therefore built the way upstream builds it: a shallow `git` checkout of the
  release commit in `.orchestrator/cache/cbom-lens/<version>/src`, then
  `go build -trimpath -ldflags "-s -w -X main.version=<version>" ./cmd/cbom-lens`; a re-run reuses the
  checkout.  It runs as `cbom-lens run --config .orchestrator/cache/cbom-lens/files/cbom-lens.yaml` in
  the case workspace.  The config (`files:` in the spec) asks for a manual one-shot scan of the case
  workspace only (named in `paths`, because cbom-lens reads a missing path list as the config file's
  directory), CBOM 1.6 on stdout (`capture_stdout`) and logs on stderr; containers, ports
  and the registry stay off.  1.6 rather than 1.7 because 1.7 replaces the `…Ref` fields the
  normaliser reads with `relatedCryptographicAssets`.  Like cbomkit-theia it scans files, not source
  code.  CBOM-Lens names itself in `metadata.component`, which the orchestrator accepts as the
  self-reported tool because the name is one of its aliases.

Edit `orchestrator/data/tools/<tool>.yaml` (or override it in `tools.d/`) to change flags, images or
queries; `orchestrator tools show <tool>` prints the effective spec.

## Configuration reference

`orchestrator init` writes a fully commented `orchestrator.yaml`; the defaults are in
`orchestrator/config.py`.  Relative paths are resolved against the directory containing the file.

## Troubleshooting

* **`docker pull … unavailable`** — the release tag has no image yet (a tag was pushed before the
  image build finished).  `fallback_tag` in the spec (`edge`/`latest`) is used automatically and
  noted in the manifest; pin to the previous version if you need exact reproducibility.
* **Root-owned output files** — containers run with `--user $(id -u):$(id -g)` by default
  (`docker.user: current`).  Set `docker.user: image` if an image refuses to run unprivileged.
* **GitHub API rate limit** — resolution falls back to `git ls-remote`; set `GITHUB_TOKEN` to use
  release metadata (pre-releases are excluded either way unless `github.allow_prerelease`).
* **CodeQL `database create` fails for Java/C#** — buildless extraction needs a recent CodeQL
  (≥ 2.16 for Java, ≥ 2.17 for C#); the bundle resolver always picks the newest.  For Go the
  extractor needs a Go toolchain on `PATH`.
* **A tool produced output but the run is `failed`** — see `logs/<tool>/<case>.log`; a non-JSON file
  or a missing output path are the usual causes.  `orchestrator normalize <file>` shows how a file is
  interpreted.
* **`cbomkit-theia` is `failed` with "the tool wrote nothing to stdout"** — theia logs `Could not scan
  dir` and still exits 0; the reason is in the stderr part of `logs/cbomkit-theia/<case>.log`.
* **`cbom-lens` is `timeout`** — in 1.1.1 a scan that fails leaves `cbom-lens run` waiting rather than
  exiting (manual mode returns only upload errors), so the orchestrator stops it after
  `timeout_seconds` (300).  `logs/cbom-lens/<case>.log` has the `scan have failed` line and its reason.
* **A language directory is missing from the run** — `baseline.include_cases`/`exclude_cases`, or
  the directory has no `ground-truth.json`.
