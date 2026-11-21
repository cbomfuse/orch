"""CBOM-Lens: the built-in spec (a config file written by `files:`, the local launcher via `go install`, the
CBOM on stdout), its self-identification in metadata.component, and the golden CBOM of its own test-suite
through normalisation, evaluation and the 2CBOM export.  `go` and cbom-lens are stand-ins here (no network
in CI); the CBOM is CBOM-Lens's own output."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from orchestrator.baseline import Case
from orchestrator.config import DEFAULT_CONFIG, Config
from orchestrator.evaluate import reported_tool
from orchestrator.normalize import read_cbom, read_cbom_file
from orchestrator.tools import builtin_spec_dir, load_specs, make_adapter
from orchestrator.tools.base import ToolVersion

COMMIT = "862a35d5fa25ac689a6a8d70c7b7b7cc54278f0b"      # tag 1.1.1
# internal/bom/testdata/golden/corpus-1.6.json of CBOM-Lens 1.1.1: certificates, keys, a CRL, a CSR,
# gitleaks findings and a TLS endpoint
GOLDEN = "cbom-lens-golden-cdx16.json"


def _case(fixtures: Path) -> Case:
    d = fixtures / "baseline-mini" / "Python"
    return Case("Python", "Python", d, d / "ground-truth.json", None, "crypto_showcase.py")


def test_spec_and_config():
    assert "cbom-lens" in DEFAULT_CONFIG["tools"]["enabled"]
    spec = load_specs(Config.defaults())["cbom-lens"]
    assert spec.launcher == "local" and spec.capture_stdout and spec.format == "cyclonedx"
    cfg = yaml.safe_load(spec.files["cbom-lens.yaml"])
    assert cfg["service"] == {"mode": "manual", "log": "stderr"}    # no dir or repository: the CBOM goes to stdout
    assert cfg["filesystem"] == {"enabled": True, "paths": []}       # the working directory, i.e. the workspace
    assert cfg["cbom"] == {"version": "1.6"}
    assert not {"containers", "ports", "registry"} & set(cfg)        # off unless configured
    assert spec.local["env"]["CBOMLENSCONFIG"] == spec.local["command"][-1]   # the variable beats --config
    assert spec.supports(Case("Rust", "Rust", Path("."), Path("gt"), None, "main.rs"))
    assert spec.twocbom["detection_method"] == "static-binary"


def test_golden_cbom_normalises(fixtures):
    norm = read_cbom_file(fixtures / "cboms" / GOLDEN)
    assert norm.metadata.tool_name is None                           # nothing in metadata.tools ...
    assert norm.metadata.component == {"type": "application", "name": "CBOM-Lens", "version": "(devel)"}
    assert norm.summary()["byType"] == {"algorithm": 13, "related-crypto-material": 10, "certificate": 3, "protocol": 1}
    cert = next(d for d in norm.by_type("certificate") if d.name == "www.ssllabs.com")
    assert (cert.attrs["signatureAlgorithmRef"], cert.attrs["subjectPublicKeyRef"]) == ("SHA256-RSA", "RSA-2048")
    tls = norm.by_type("protocol")[0]
    assert tls.attrs["version"] == "1.3" and len(tls.attrs["cipherSuites"]) == 3
    assert not norm.warnings


def test_reported_tool_from_metadata_component(fixtures):
    aliases = load_specs(Config.defaults())["cbom-lens"].twocbom["aliases"]
    golden = read_cbom_file(fixtures / "cboms" / GOLDEN)
    assert reported_tool(golden, aliases)["name"] == "CBOM-Lens"     # ... so the component names the producer
    assert reported_tool(golden, ["some-other-tool"]) is None
    doc = json.loads((fixtures / "cboms" / "cdxgen-python-cdx16.json").read_text())
    assert reported_tool(read_cbom(doc), [])["name"] == "@cyclonedx/cdxgen"      # metadata.tools comes first
    del doc["metadata"]["tools"]                                    # its component is the scanned project
    assert reported_tool(read_cbom(doc), ["cdxgen"]) is None


FAKE_GO = """#!{python}
import json, os, shutil, sys
args = sys.argv[1:]
keys = ("GOBIN", "GOPATH", "GOCACHE", "GOFLAGS", "GOTOOLCHAIN", "CGO_ENABLED", "CBOMLENSCONFIG")
with open(os.environ["FAKE_GO_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": args, "env": {{k: os.environ.get(k) for k in keys}}}}) + "\\n")
if args[0] == "install":
    os.makedirs(os.environ["GOBIN"], exist_ok=True)            # go install creates GOBIN
    exe = os.path.join(os.environ["GOBIN"], "cbom-lens")
    shutil.copy({lens!r}, exe)
    os.chmod(exe, 0o755)
"""

FAKE_LENS = """#!{python}
import json, os, sys
import yaml
args = sys.argv[1:]
if args == ["version"]:
    print("cbom-lens: 1.1.1")
    print("go:     go1.26.9")
    sys.exit(0)
assert args[:2] == ["run", "--config"], args
cfg = yaml.safe_load(open(os.environ.get("CBOMLENSCONFIG") or args[2]))     # cmd/cbom-lens: the variable wins
assert cfg["service"]["mode"] == "manual" and cfg["filesystem"] == {{"enabled": True, "paths": []}}, cfg
assert os.path.isfile("crypto_showcase.py")                     # paths: [] scans the working directory
sys.stderr.write(json.dumps({{"level": "INFO", "msg": "scan finished"}}) + "\\n")
sys.stdout.write(open({golden!r}).read())
"""


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(os.name == "nt", reason="stand-in executables use a shebang")
def test_local_install_and_run(tmp_path, fixtures, monkeypatch):
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    lens = _executable(tmp_path / "cbom-lens.py", FAKE_LENS.format(python=sys.executable, golden=str(fixtures / "cboms" / GOLDEN)))
    _executable(fake_bin / "go", FAKE_GO.format(python=sys.executable, lens=str(lens)))
    go_log = tmp_path / "go.log"
    monkeypatch.setenv("FAKE_GO_LOG", str(go_log))
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    config = Config.defaults(tmp_path)
    adapter = make_adapter(load_specs(config)["cbom-lens"], config)
    version = ToolVersion.fixed("cbom-lens", "CBOM-Lens", "1.1.1", tag="1.1.1", commit=COMMIT, launcher="local")
    adapter.install(version, tmp_path / "install.log")

    cache = config.path("tools", "cache_dir") / "cbom-lens"
    conf = cache / "files" / "cbom-lens.yaml"
    (install,) = [json.loads(line) for line in go_log.read_text().splitlines()]
    assert install["argv"] == ["install", "-ldflags=-X main.version=1.1.1",
                               f"github.com/OmniTrustILM/cbom-lens/cmd/cbom-lens@{COMMIT}"]
    assert install["env"] == {"GOBIN": str(cache / "1.1.1" / "bin"), "GOPATH": str(cache / "go"),
                              "GOCACHE": str(cache / "go-build"), "GOFLAGS": "-modcacherw", "GOTOOLCHAIN": "auto",
                              "CGO_ENABLED": "0", "CBOMLENSCONFIG": str(conf)}
    assert version.components["check"].startswith("cbom-lens: 1.1.1")

    work = tmp_path / "work"
    shutil.copytree(_case(fixtures).dir, work)
    res = adapter.run(_case(fixtures), work, version, tmp_path / "raw", tmp_path / "run.log")
    assert res.status == "ok", res.notes
    assert res.command == [str(cache / "1.1.1" / "bin" / "cbom-lens"), "run", "--config", str(conf)]
    assert conf.read_text() == load_specs(config)["cbom-lens"].files["cbom-lens.yaml"]
    assert res.output_path.read_bytes() == (fixtures / "cboms" / GOLDEN).read_bytes()
    log = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "--- stdout -> " in log and "scan finished" in log and "www.ssllabs.com" not in log


def test_runner_reports_and_exports_cbom_lens(tmp_path, fixtures):
    from orchestrator.evaluate import evaluate_run
    from orchestrator.export import write_outputs
    from orchestrator.runner import Runner

    corpus = tmp_path / "corpus"
    shutil.copytree(fixtures / "baseline-mini", corpus)
    lens = tmp_path / "cbom-lens.py"
    lens.write_text(FAKE_LENS.format(python=sys.executable, golden=str(fixtures / "cboms" / GOLDEN)))
    # the built-in spec, files: and all, with the stand-in as its command (no repo: no version lookup)
    spec = yaml.safe_load((builtin_spec_dir() / "cbom-lens.yaml").read_text())
    spec.update({"repo": None, "local": {"command": [sys.executable, str(lens), "run", "--config", "{files}/cbom-lens.yaml"]}})
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    (tools_d / "cbom-lens.yaml").write_text(yaml.safe_dump(spec))
    cfg = {"baseline": {"repo": str(corpus)}, "results": {"dir": str(tmp_path / "results"), "latest_symlink": False},
           "tools": {"enabled": ["cbom-lens"], "cache_dir": str(tmp_path / "cache"), "dir": str(tools_d)}}
    (tmp_path / "orchestrator.yaml").write_text(yaml.safe_dump(cfg))
    config = Config.load(tmp_path / "orchestrator.yaml")

    run_dir = Runner(config, run_id="lens").execute()
    rec = json.loads((run_dir / "manifest.json").read_text())["runs"][0]
    assert (rec["status"], rec["output"]) == ("ok", "raw/cbom-lens/Python/cbom.cbom-lens.json")
    doc = evaluate_run(run_dir, config)
    assert (doc["tools"]["cbom-lens"]["reported"]["name"], doc["tools"]["cbom-lens"]["reported"]["version"]) == \
        ("CBOM-Lens", "(devel)")
    assert doc["coverage"]["cbom-lens"] == {"Python": "ok"}
    write_outputs(doc, run_dir, config)
    entry = json.loads((run_dir / "twocbom" / "tools.json").read_text())["tools"]["cbom-lens"]
    assert entry["detectionMethod"] == "static-binary" and entry["benchmark"]["reportedVersion"] == "(devel)"
    assert len(entry["aliases"]) == len(spec["twocbom"]["aliases"])            # "CBOM-Lens" is already an alias
