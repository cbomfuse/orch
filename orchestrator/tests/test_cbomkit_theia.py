"""CBOMkit-theia: the built-in spec with both launchers, stdout capture, and theia's CBOM shape through
normalisation, evaluation and the 2CBOM export.  Docker, `go` and theia itself are stand-ins (no Docker
or network in CI)."""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml

from orchestrator.baseline import Case
from orchestrator.config import DEFAULT_CONFIG, Config, default_config_yaml
from orchestrator.docker import DockerError
from orchestrator.normalize import read_cbom
from orchestrator.process import CommandResult
from orchestrator.tools import builtin_spec_dir, load_specs, make_adapter
from orchestrator.tools.base import ToolVersion

COMMIT = "dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59"      # tag v1.1.2


def _alg(ref, name, oid=None, **props):
    comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "evidence": {"occurrences": [{"location": "certs/server.pem"}]},
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props}}
    if oid:
        comp["cryptoProperties"]["oid"] = oid
    return comp


# What `cbomkit-theia dir` (v1.1.2) prints for a directory with a self-signed RSA certificate and a source
# file holding a hard-coded key: components as built by scanner/x509, scanner/key and the secrets plugin,
# metadata.tools.services as written by scanner.addMetadata (the plugins nested under the tool).  Real
# bom-refs are UUIDs.
THEIA_BOM = {
    "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
    "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:4d0c2b5e-8f0e-4a43-9d55-0f1f6b7d0b1e",
    "version": 1,
    "metadata": {
        "timestamp": "2026-11-20T16:00:00-08:00",
        "tools": {"services": [{
            "provider": {"name": "PQCA"}, "name": "cbomkit-theia", "version": "v1.1.2",
            "services": [{"name": "Certificate File Plugin"}, {"name": "Secret Detection Plugin"},
                         {"name": "OpenSSL Configuration Plugin"}, {"name": "Problematic CA Detection Plugin"}],
        }]},
    },
    "components": [
        _alg("sig-rsa", "RSA", "1.2.840.113549.1.1.1", primitive="signature", cryptoFunctions=["sign"]),
        _alg("hash-sha256", "SHA256", primitive="hash", parameterSetIdentifier="256", cryptoFunctions=["digest"]),
        _alg("sig-sha256-rsa", "SHA256-RSA", "1.2.840.113549.1.1.11", primitive="signature",
             parameterSetIdentifier="256", padding="pkcs1v15", cryptoFunctions=["sign"]),
        _alg("pke-rsa", "RSA", "1.2.840.113549.1.1.1", primitive="pke",
             cryptoFunctions=["encapsulate", "decapsulate", "sign"]),
        {"type": "cryptographic-asset", "bom-ref": "pub-rsa-2048", "name": "RSA-2048",
         "evidence": {"occurrences": [{"location": "certs/server.pem"}]},
         "cryptoProperties": {"assetType": "related-crypto-material", "oid": "1.2.840.113549.1.1.1",
                              "relatedCryptoMaterialProperties": {"type": "public-key", "algorithmRef": "pke-rsa",
                                                                  "size": 2048, "format": "PEM"}}},
        {"type": "cryptographic-asset", "bom-ref": "cert", "name": "cbom-corpus.example",
         "evidence": {"occurrences": [{"location": "certs/server.pem"}]},
         "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
             "subjectName": "cbom-corpus.example", "issuerName": "cbom-corpus.example",
             "notValidBefore": "2026-01-01T00:00:00Z", "notValidAfter": "2027-01-01T00:00:00Z",
             "signatureAlgorithmRef": "sig-sha256-rsa", "subjectPublicKeyRef": "pub-rsa-2048",
             "certificateFormat": "X.509", "certificateExtension": "pem"}}},
        {"type": "cryptographic-asset", "bom-ref": "secret-1", "name": "generic-api-key",
         "description": "Detected a Generic API Key, potentially exposing access to various services.",
         "evidence": {"occurrences": [{"location": "crypto_showcase.py", "line": 56}]},
         "cryptoProperties": {"assetType": "related-crypto-material",
                              "relatedCryptoMaterialProperties": {"type": "key"}}},
    ],
    "dependencies": [{"ref": "sig-sha256-rsa", "dependsOn": ["sig-rsa", "hash-sha256"]}],
}


def _case(fixtures: Path) -> Case:
    d = fixtures / "baseline-mini" / "Python"
    return Case("Python", "Python", d, d / "ground-truth.json", None, "crypto_showcase.py")


def _workspace(tmp_path: Path, fixtures: Path) -> Path:
    work = tmp_path / "work"
    shutil.copytree(_case(fixtures).dir, work)
    return work


def _version(launcher: str) -> ToolVersion:
    return ToolVersion.fixed("cbomkit-theia", "CBOMkit-theia", "1.1.2", tag="v1.1.2", commit=COMMIT, launcher=launcher)


class FakeDocker:
    """Records `docker run`; plays the theia container by writing ``stdout`` to the capture file."""

    def __init__(self, stdout: bytes, missing=()):
        self.stdout, self.missing, self.calls, self.pulled = stdout, set(missing), [], []

    def available(self):
        return True

    def pull(self, image, log_path=None):
        if image in self.missing:
            raise DockerError(f"docker pull {image} failed: manifest unknown")
        self.pulled.append(image)

    def image_digest(self, image):
        return image.rsplit(":", 1)[0] + "@sha256:" + "0" * 64

    def image_id(self, image):
        return "sha256:" + "1" * 64

    def image_label(self, image, label):
        return {"org.opencontainers.image.version": "1.1.2", "org.opencontainers.image.revision": COMMIT}.get(label)

    def run(self, image, args, **kw):
        self.calls.append({"image": image, "args": list(args), **kw})
        Path(kw["stdout_path"]).write_bytes(self.stdout)
        return CommandResult(["docker", "run", "--rm", image, *args], 0, "", 'level=info msg="=> Running Secret Detection Plugin"\n', 0.2)


# ----------------------------------------------------------------------------- spec
def test_spec_is_enabled_and_language_agnostic():
    assert "cbomkit-theia" in DEFAULT_CONFIG["tools"]["enabled"]
    assert yaml.safe_load(default_config_yaml())["tools"]["enabled"] == DEFAULT_CONFIG["tools"]["enabled"]
    project = yaml.safe_load((Path(__file__).parents[1] / "orchestrator.yaml").read_text())
    assert project["tools"]["enabled"] == DEFAULT_CONFIG["tools"]["enabled"]
    spec = load_specs(Config.defaults())["cbomkit-theia"]
    assert spec.capture_stdout and spec.format == "cyclonedx" and spec.launcher == "docker"
    for lang in ("Python", "Java", "Go", "TypeScript", "C#", "Rust"):          # Rust: a case added later
        assert spec.supports(Case(lang, lang, Path("."), Path("gt"), None, "x"))
    # the same identity 2CBOM's knowledge/tools.json uses, so the exported entry replaces it cleanly
    assert spec.twocbom["detection_method"] == "static-binary"
    assert {"cbomkit-theia", "theia"} <= set(spec.twocbom["aliases"])


# ----------------------------------------------------------------------------- docker launcher
def test_docker_launcher(tmp_path, fixtures):
    config = Config.defaults(tmp_path)
    docker = FakeDocker(json.dumps(THEIA_BOM).encode("utf-8"))
    adapter = make_adapter(load_specs(config)["cbomkit-theia"], config, docker)
    version = _version("docker")
    adapter.install(version)
    assert version.image == "ghcr.io/cbomkit/cbomkit-theia:1.1.2"          # bare version, like the CI tags it
    assert version.components["org.opencontainers.image.version"] == "1.1.2"
    work = _workspace(tmp_path, fixtures)
    res = adapter.run(_case(fixtures), work, version, tmp_path / "raw", tmp_path / "log.txt")
    assert res.status == "ok", res.notes
    call = docker.calls[0]
    assert call["image"] == "ghcr.io/cbomkit/cbomkit-theia:1.1.2"
    assert call["args"] == ["dir", "/src"]
    assert call["mounts"] == {str(work): "/src"}
    assert call["network"] == "none" and call["env"] == {"HOME": "/tmp"} and call["user"] == "current"
    assert call["stdout_path"] == work / "cbom.theia.json"
    assert res.output_path == tmp_path / "raw" / "cbom.theia.json"
    assert json.loads(res.output_path.read_text(encoding="utf-8")) == THEIA_BOM


def test_docker_falls_back_to_edge(tmp_path):
    config = Config.defaults(tmp_path)
    docker = FakeDocker(b"", missing={"ghcr.io/cbomkit/cbomkit-theia:1.1.2"})
    adapter = make_adapter(load_specs(config)["cbomkit-theia"], config, docker)
    version = _version("docker")
    adapter.install(version)
    assert version.image == "ghcr.io/cbomkit/cbomkit-theia:edge"
    assert any("edge" in n for n in version.notes)


def test_scan_error_with_exit_zero_is_failed(tmp_path, fixtures):
    """theia logs "Could not scan dir" and exits 0 with nothing on stdout."""
    config = Config.defaults(tmp_path)
    adapter = make_adapter(load_specs(config)["cbomkit-theia"], config, FakeDocker(b""))
    work = _workspace(tmp_path, fixtures)
    res = adapter.run(_case(fixtures), work, _version("docker"), tmp_path / "raw", tmp_path / "log.txt")
    assert res.status == "failed" and res.output_path is None
    assert any("nothing to stdout" in n for n in res.notes)
    assert not (work / "cbom.theia.json").exists()


# ----------------------------------------------------------------------------- local launcher
FAKE_GO = """#!{python}
import json, os, shutil, sys
args = sys.argv[1:]
keys = ("GOBIN", "GOPATH", "GOCACHE", "GOFLAGS", "GOTOOLCHAIN", "CGO_ENABLED", "HOME")
with open(os.environ["FAKE_GO_LOG"], "a") as fh:
    fh.write(json.dumps({{"argv": args, "env": {{k: os.environ.get(k) for k in keys}}}}) + "\\n")
if args[0] == "install":
    os.makedirs(os.environ["GOBIN"], exist_ok=True)            # go install creates GOBIN
    exe = os.path.join(os.environ["GOBIN"], "cbomkit-theia")
    shutil.copy({theia!r}, exe)
    os.chmod(exe, 0o755)
elif args[:2] == ["version", "-m"]:
    print(args[2] + ": go1.26.8")
    print("\\tmod\\tgithub.com/cbomkit/cbomkit-theia\\tv1.1.2\\th1:stub=")
"""

FAKE_THEIA = """#!{python}
import json, os, sys
try:
    os.mkdir(os.path.join(os.environ["HOME"], ".cbomkit-theia"))    # cmd/root.go, first run
except FileExistsError:
    pass
except OSError as exc:
    print(exc)                                                       # theia prints this one on stdout
assert sys.argv[1] == "dir" and os.path.isdir(sys.argv[2])
sys.stderr.write('level=info msg="=> Running Certificate File Plugin"\\n')
print(json.dumps({bom}))
"""


def _executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(os.name == "nt", reason="stand-in executables use a shebang")
def test_local_launcher_builds_and_runs(tmp_path, fixtures, monkeypatch):
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    theia = _executable(tmp_path / "theia.py", FAKE_THEIA.format(python=sys.executable, bom=repr(THEIA_BOM)))
    _executable(fake_bin / "go", FAKE_GO.format(python=sys.executable, theia=str(theia)))
    go_log = tmp_path / "go.log"
    monkeypatch.setenv("FAKE_GO_LOG", str(go_log))
    monkeypatch.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")

    config = Config.defaults(tmp_path)
    config.data["tools"]["default_launcher"] = "local"                   # what --launcher local does
    adapter = make_adapter(load_specs(config)["cbomkit-theia"], config)
    version = _version("local")
    adapter.install(version, tmp_path / "install.log")

    cache = config.path("tools", "cache_dir") / "cbomkit-theia"
    install, check = [json.loads(line) for line in go_log.read_text().splitlines()]
    assert install["argv"] == ["install", "-ldflags=-X github.com/cbomkit/cbomkit-theia/scanner.Version=v1.1.2",
                               f"github.com/cbomkit/cbomkit-theia@{COMMIT}"]
    assert install["env"] == {"GOBIN": str(cache / "1.1.2" / "bin"), "GOPATH": str(cache / "go"),
                              "GOCACHE": str(cache / "go-build"), "GOFLAGS": "-modcacherw", "GOTOOLCHAIN": "auto",
                              "CGO_ENABLED": "0", "HOME": str(cache / "1.1.2")}
    assert check["argv"] == ["version", "-m", str(cache / "1.1.2" / "bin" / "cbomkit-theia")]
    assert "go1.26.8" in version.components["check"]

    work = _workspace(tmp_path, fixtures)
    res = adapter.run(_case(fixtures), work, version, tmp_path / "raw", tmp_path / "run.log")
    assert res.status == "ok", res.notes
    assert res.command == [str(cache / "1.1.2" / "bin" / "cbomkit-theia"), "dir", str(work)]
    assert json.loads(res.output_path.read_text(encoding="utf-8")) == THEIA_BOM
    assert (cache / "1.1.2" / ".cbomkit-theia").is_dir()                 # theia's config lives in the per-version home
    log = (tmp_path / "run.log").read_text(encoding="utf-8")
    assert "--- stdout -> " in log and "Running Certificate File Plugin" in log and "generic-api-key" not in log


# ----------------------------------------------------------------------------- normalise, evaluate, export
def test_theia_cbom_normalises():
    norm = read_cbom(THEIA_BOM)
    assert (norm.metadata.tool_name, norm.metadata.tool_version) == ("cbomkit-theia", "v1.1.2")
    assert [t["name"] for t in norm.metadata.tools] == ["cbomkit-theia"]    # plugins are not separate tools
    assert norm.summary()["byType"] == {"algorithm": 4, "related-crypto-material": 2, "certificate": 1}
    cert = norm.by_type("certificate")[0]
    assert cert.attrs["signatureAlgorithmRef"] == "SHA256-RSA" and cert.attrs["subjectPublicKeyRef"] == "RSA-2048"
    assert cert.attrs["certificateFormat"] == "X.509" and cert.occurrences[0].file == "certs/server.pem"
    key = next(d for d in norm.detections if d.name == "generic-api-key")
    assert (key.occurrences[0].file, key.occurrences[0].line) == ("crypto_showcase.py", 56)
    assert not norm.warnings


def test_runner_scores_and_exports_theia(tmp_path, fixtures):
    from orchestrator.evaluate import evaluate_run
    from orchestrator.export import write_outputs
    from orchestrator.runner import Runner

    corpus = tmp_path / "corpus"
    shutil.copytree(fixtures / "baseline-mini", corpus)
    script = tmp_path / "theia.py"
    script.write_text(f"import json, sys\nsys.stderr.write('scanning ' + sys.argv[2] + '\\n')\nprint(json.dumps({THEIA_BOM!r}))\n")
    # the built-in spec with the launcher swapped for the stand-in (no repo: no version lookup)
    spec = yaml.safe_load((builtin_spec_dir() / "cbomkit-theia.yaml").read_text())
    spec.update({"repo": None, "launcher": "local", "local": {"command": [sys.executable, str(script), "dir", "{workdir}"]}})
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    (tools_d / "cbomkit-theia.yaml").write_text(yaml.safe_dump(spec))
    cfg = {"baseline": {"repo": str(corpus)}, "results": {"dir": str(tmp_path / "results"), "latest_symlink": False},
           "tools": {"enabled": ["cbomkit-theia", "oracle"], "cache_dir": str(tmp_path / "cache"), "dir": str(tools_d)}}
    (tmp_path / "orchestrator.yaml").write_text(yaml.safe_dump(cfg))
    config = Config.load(tmp_path / "orchestrator.yaml")

    run_dir = Runner(config, run_id="theia").execute()
    manifest = json.loads((run_dir / "manifest.json").read_text())
    rec = next(r for r in manifest["runs"] if r["tool"] == "cbomkit-theia")
    assert rec["status"] == "ok" and rec["output"] == "raw/cbomkit-theia/Python/cbom.theia.json"
    assert manifest["tools"]["cbomkit-theia"]["spec"]["capture_stdout"] is True

    doc = evaluate_run(run_dir, config)
    assert doc["tools"]["cbomkit-theia"]["reported"]["name"] == "cbomkit-theia"
    assert doc["tools"]["cbomkit-theia"]["reported"]["version"] == "v1.1.2"
    ev = next(r for r in doc["runs"] if r["tool"] == "cbomkit-theia")["evaluation"]
    assert ev["detections"] == 7 and ev["status"] == "ok"
    assert doc["coverage"]["cbomkit-theia"] == {"Python": "ok"}

    write_outputs(doc, run_dir, config)
    entry = json.loads((run_dir / "twocbom" / "tools.json").read_text())["tools"]["cbomkit-theia"]
    assert entry["detectionMethod"] == "static-binary"
    assert {"cbomkit-theia", "theia"} <= set(entry["aliases"])
    assert entry["benchmark"]["reportedVersion"] == "v1.1.2"
    assert "cbomkit-theia" in (run_dir / "report.md").read_text()
