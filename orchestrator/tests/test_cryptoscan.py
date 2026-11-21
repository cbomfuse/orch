"""CryptoScan: the built-in spec (local launcher via `go install`), its exit-code convention, and a real CBOM
from CryptoScan 1.5.0 through normalisation, matching and the 2CBOM export.  `go` and the scanner are
stand-ins here (no network in CI); the CBOM is the scanner's genuine output for the vendored Python case."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from orchestrator.baseline import Case, GroundTruth
from orchestrator.config import DEFAULT_CONFIG, Config
from orchestrator.evaluate.ledger import evaluate_case
from orchestrator.normalize import read_cbom_file
from orchestrator.tools import builtin_spec_dir, load_specs, make_adapter
from orchestrator.tools.base import ToolVersion

COMMIT = "71c7f0e2944e1d0a5819246eab66f2a8da70d0a8e4"      # tag v1.5.0
# `cryptoscan scan <case> --format cbom --include-quantum-safe --no-config` (1.5.0) on baseline-mini/Python
REAL = "cryptoscan-python-cdx16.json"


def _case(fixtures: Path) -> Case:
    d = fixtures / "baseline-mini" / "Python"
    return Case("Python", "Python", d, d / "ground-truth.json", None, "crypto_showcase.py")


def test_spec(fixtures):
    assert "cryptoscan" in DEFAULT_CONFIG["tools"]["enabled"]
    spec = load_specs(Config.defaults())["cryptoscan"]
    assert spec.launcher == "local" and not spec.docker and spec.ok_exit_codes == [0, 1]
    assert spec.supports(Case("Rust", "Rust", Path("."), Path("gt"), None, "main.rs"))
    assert spec.twocbom["detection_method"] == "static-source"
    # the name the orchestrator reads from CryptoScan's CBOMs is already an alias, so 2CBOM resolves it
    reported = read_cbom_file(fixtures / "cboms" / REAL).metadata.tool_name
    assert reported.lower() in {a.lower() for a in spec.twocbom["aliases"]}


FAKE_GO = """#!{python}
import json, os, shutil, sys
args = sys.argv[1:]
keys = ("GOBIN", "GOPATH", "GOCACHE", "GOFLAGS", "GOTOOLCHAIN", "CGO_ENABLED")
with open(os.environ["FAKE_GO_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": args, "env": {{k: os.environ.get(k) for k in keys}}}}) + "\\n")
if args[0] == "install":
    os.makedirs(os.environ["GOBIN"], exist_ok=True)            # go install creates GOBIN
    exe = os.path.join(os.environ["GOBIN"], "cryptoscan")
    shutil.copy({scanner!r}, exe)
    os.chmod(exe, 0o755)
"""

FAKE_CRYPTOSCAN = """#!{python}
import shutil, sys
args = sys.argv[1:]
if args == ["version"]:
    print("cryptoscan 1.5.0")
    print()
    print("Part of QRAMM - https://qramm.org")
    sys.exit(0)
assert args[0] == "scan" and args[2:6] == ["--format", "cbom", "--include-quantum-safe", "--no-config"], args
shutil.copy({cbom!r}, args[args.index("--output") + 1])
sys.exit(1)                                                   # a CRITICAL finding, as on every corpus case
"""


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(os.name == "nt", reason="stand-in executables use a shebang")
def test_local_install_and_run(tmp_path, fixtures, monkeypatch):
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    scanner = _executable(tmp_path / "cryptoscan.py",
                          FAKE_CRYPTOSCAN.format(python=sys.executable, cbom=str(fixtures / "cboms" / REAL)))
    _executable(fake_bin / "go", FAKE_GO.format(python=sys.executable, scanner=str(scanner)))
    go_log = tmp_path / "go.log"
    monkeypatch.setenv("FAKE_GO_LOG", str(go_log))
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    config = Config.defaults(tmp_path)
    adapter = make_adapter(load_specs(config)["cryptoscan"], config)
    version = ToolVersion.fixed("cryptoscan", "CryptoScan", "1.5.0", tag="v1.5.0", commit=COMMIT, launcher="local")
    adapter.install(version, tmp_path / "install.log")

    cache = config.path("tools", "cache_dir") / "cryptoscan"
    (install,) = [json.loads(line) for line in go_log.read_text().splitlines()]
    assert install["argv"] == ["install", "-ldflags=-X main.version=1.5.0",
                               f"github.com/csnp/cryptoscan/cmd/cryptoscan@{COMMIT}"]
    assert install["env"] == {"GOBIN": str(cache / "1.5.0" / "bin"), "GOPATH": str(cache / "go"),
                              "GOCACHE": str(cache / "go-build"), "GOFLAGS": "-modcacherw", "GOTOOLCHAIN": "auto",
                              "CGO_ENABLED": "0"}
    assert version.components["check"].startswith("cryptoscan 1.5.0")

    work = tmp_path / "work"
    shutil.copytree(_case(fixtures).dir, work)
    res = adapter.run(_case(fixtures), work, version, tmp_path / "raw", tmp_path / "run.log")
    assert res.command == [str(cache / "1.5.0" / "bin" / "cryptoscan"), "scan", str(work), "--format", "cbom",
                           "--include-quantum-safe", "--no-config", "--output", str(work / "cbom.cryptoscan.json")]
    assert res.status == "ok" and res.exit_code == 1 and res.notes == []     # exit 1 = findings, not a failure
    assert res.output_path.read_bytes() == (fixtures / "cboms" / REAL).read_bytes()


def test_real_cbom_matches_family_names(fixtures):
    """CryptoScan names families; the lexicon resolves SHAKE (-> SHA-3 XOF) and ECC (-> generic EC)."""
    norm = read_cbom_file(fixtures / "cboms" / REAL)
    gt = GroundTruth.load(fixtures / "baseline-mini" / "Python" / "ground-truth.json", "Python")
    ev = evaluate_case(gt, norm, "cryptoscan", "1.5.0")
    ref = {d.name: d.ref for d in norm.detections}

    def assets_of(name):
        return {r["assetId"] for r in ev.rows if ref[name] in r["detectionRefs"]}

    assert "shake128" in assets_of("SHAKE")
    assert {"ecdsa-p256-sha256", "ecdh-p256", "ed25519"} <= assets_of("ECC")     # half credit, family only
    assert assets_of("AES") and assets_of("SHA-2")              # the findings --include-quantum-safe adds
    assert ref["ECC"] not in {r["ref"] for r in ev.fp_rows}


def test_runner_scores_and_exports_cryptoscan(tmp_path, fixtures):
    from orchestrator.evaluate import evaluate_run
    from orchestrator.export import write_outputs
    from orchestrator.runner import Runner

    corpus = tmp_path / "corpus"
    shutil.copytree(fixtures / "baseline-mini", corpus)
    script = tmp_path / "cryptoscan.py"
    script.write_text(f"import shutil, sys\nshutil.copy({str(fixtures / 'cboms' / REAL)!r}, sys.argv[-1])\nsys.exit(1)\n")
    # the built-in spec with the stand-in as its command (no repo: no version lookup, no install)
    spec = yaml.safe_load((builtin_spec_dir() / "cryptoscan.yaml").read_text())
    spec.update({"repo": None, "local": {"command": [sys.executable, str(script), "--output", "{output}"]}})
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    (tools_d / "cryptoscan.yaml").write_text(yaml.safe_dump(spec))
    cfg = {"baseline": {"repo": str(corpus)}, "results": {"dir": str(tmp_path / "results"), "latest_symlink": False},
           "tools": {"enabled": ["cryptoscan"], "cache_dir": str(tmp_path / "cache"), "dir": str(tools_d)}}
    (tmp_path / "orchestrator.yaml").write_text(yaml.safe_dump(cfg))
    config = Config.load(tmp_path / "orchestrator.yaml")

    run_dir = Runner(config, run_id="cs").execute()
    rec = json.loads((run_dir / "manifest.json").read_text())["runs"][0]
    assert (rec["status"], rec["exitCode"], rec["notes"]) == ("ok", 1, [])
    doc = evaluate_run(run_dir, config)
    assert doc["tools"]["cryptoscan"]["reported"]["name"] == "CSNP CryptoScan"
    assert doc["summary"]["cryptoscan"]["detected"] > 0
    write_outputs(doc, run_dir, config)
    entry = json.loads((run_dir / "twocbom" / "tools.json").read_text())["tools"]["cryptoscan"]
    assert entry["detectionMethod"] == "static-source"
    assert entry["benchmark"]["reportedVersion"] == "1.5.0"
    assert len(entry["aliases"]) == len(spec["twocbom"]["aliases"])           # the reported name was no new alias
