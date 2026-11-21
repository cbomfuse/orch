"""The YAML-driven adapter renders commands without running anything (no Docker in CI)."""
import json
from pathlib import Path

from orchestrator.baseline import Case
from orchestrator.config import Config
from orchestrator.tools import load_specs, make_adapter
from orchestrator.tools.base import ToolVersion, render


def test_builtin_specs_load():
    specs = load_specs(Config.defaults())
    assert {"cbomkit", "cdxgen", "cryptobom-forge", "cbomkit-theia", "oracle"} <= set(specs)
    assert specs["cbomkit"].supports(Case("Java", "Java", Path("."), Path("gt"), None, "X.java"))
    assert not specs["cbomkit"].supports(Case("TypeScript", "TypeScript", Path("."), Path("gt"), None, "x.ts"))
    assert specs["cdxgen"].language_entry(Case("CSharp", "C#", Path("."), Path("gt"), None, "P.cs")) == {"value": "dotnet"}


def test_placeholders_render(tmp_path):
    config = Config.defaults(tmp_path)
    spec = load_specs(config)["cdxgen"]
    adapter = make_adapter(spec, config)
    version = ToolVersion.fixed("cdxgen", "cdxgen", "13.6.0", tag="v13.6.0", launcher="docker")
    case = Case("Python", "Python", tmp_path, tmp_path / "gt.json", None, "crypto_showcase.py")
    variables = adapter.variables(version, case, tmp_path / "work", {"mount": "/app", "output_container": "/app/out.json"})
    args = render(spec.docker["args"], variables)
    assert args[:2] == ["-t", "python"] and "--include-crypto" in args and args[-1] == "/app"
    assert render(spec.docker["image"], variables) == "ghcr.io/cyclonedx/cdxgen:v13.6.0"
    cb = load_specs(config)["cbomkit"]
    assert render(cb.docker["image"], adapter.variables(ToolVersion.fixed("cbomkit", "x", "2.3.0", tag="v2.3.0"))) == \
        "ghcr.io/cbomkit/cbomkit-action:2.3.0"


def test_unsupported_language_short_circuits(tmp_path):
    config = Config.defaults(tmp_path)
    adapter = make_adapter(load_specs(config)["cbomkit"], config)
    case = Case("TypeScript", "TypeScript", tmp_path, tmp_path / "gt.json", None, "x.ts")
    res = adapter.run(case, tmp_path / "w", ToolVersion.fixed("cbomkit", "x", "2.3.0"), tmp_path / "o", tmp_path / "l.log")
    assert res.status == "unsupported"


def test_local_launcher_end_to_end(tmp_path, fixtures):
    """A fake local tool (a Python one-liner) proves the local launcher, output lookup and status rules."""
    import json
    import sys
    import yaml
    from orchestrator.tools import load_specs, make_adapter
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    script = tmp_path / "faketool.py"
    script.write_text(
        "import json, sys\n"
        "out, lang = sys.argv[1], sys.argv[2]\n"
        "doc = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'metadata': {'tools': {'components': [{'name': 'faketool', 'version': '9.9'}]}},\n"
        "       'components': [] if lang == 'empty' else [{'type': 'cryptographic-asset', 'bom-ref': 'x', 'name': 'SHA-256',\n"
        "       'cryptoProperties': {'assetType': 'algorithm', 'algorithmProperties': {'primitive': 'hash'}}}]}\n"
        "json.dump(doc, open(out, 'w'))\n")
    (tools_d / "faketool.yaml").write_text(yaml.safe_dump({
        "id": "faketool", "name": "Fake", "repo": None, "launcher": "local",
        "local": {"command": [sys.executable, str(script), "{output}", "{language}"]},
        "output": "out/fake.json", "languages": {"Python": "python", "Go": "empty"}}))
    config = Config.defaults(tmp_path)
    config.data["tools"]["dir"] = str(tools_d)
    config.data["tools"]["cache_dir"] = str(tmp_path / "cache")
    adapter = make_adapter(load_specs(config)["faketool"], config)
    version = adapter.resolve()
    assert version.version == "unversioned" and version.launcher == "local"
    case = Case("Python", "Python", fixtures / "baseline-mini" / "Python", fixtures / "baseline-mini" / "Python" / "ground-truth.json", None, "crypto_showcase.py")
    work = tmp_path / "work"
    work.mkdir()
    (work / "out").mkdir()
    res = adapter.run(case, work, version, tmp_path / "raw", tmp_path / "log.txt")
    assert res.status == "ok" and res.output_path and res.output_path.exists()
    assert json.load(open(res.output_path))["components"]
    empty_case = Case("Go", "Go", case.dir, case.ground_truth, None, "main.go")
    res2 = adapter.run(empty_case, work, version, tmp_path / "raw2", tmp_path / "log.txt")
    assert res2.status == "empty"
    assert "faketool" in (tmp_path / "log.txt").read_text()


def test_language_wildcard():
    from orchestrator.tools.base import ToolSpec
    spec = ToolSpec.from_dict({"id": "scanner", "languages": {"*": "any", "Java": "java", "Go": {"unsupported": True}}})
    rust = Case("Rust", "Rust", Path("."), Path("gt"), None, "main.rs")
    assert spec.supports(rust) and spec.language_entry(rust) == {"value": "any"}
    assert spec.language_entry(Case("Java", "Java", Path("."), Path("gt"), None, "X.java")) == {"value": "java"}
    assert not spec.supports(Case("Go", "Go", Path("."), Path("gt"), None, "main.go"))       # own entry wins


def test_run_command_streams_stdout_to_a_file(tmp_path):
    import sys
    from orchestrator.process import run_command
    child = "import sys; sys.stdout.buffer.write('{\"subject\": \"Z\\u00fcrich CA\"}'.encode()); sys.stderr.write('log line')"
    out = tmp_path / "sub" / "stdout.json"
    res = run_command([sys.executable, "-c", child], stdout_path=out, log_path=tmp_path / "log.txt")
    assert res.ok and res.stdout == "" and res.stderr == "log line"
    assert out.read_bytes() == '{"subject": "Zürich CA"}'.encode("utf-8")      # bytes as written, any locale
    assert res.extra["stdoutBytes"] == out.stat().st_size
    log = (tmp_path / "log.txt").read_text(encoding="utf-8")
    assert f"--- stdout -> {out} ({out.stat().st_size} bytes) ---" in log and "Zürich" not in log


def test_capture_stdout_spec(tmp_path, fixtures):
    """A tool that prints its CBOM: stdout becomes `output`; exit 0 with empty stdout is a failure."""
    import sys
    import yaml
    script = tmp_path / "printer.py"
    script.write_text(
        "import json, sys\n"
        "sys.stderr.write('scanning ' + sys.argv[2] + '\\n')\n"
        "if sys.argv[1] == 'loud':\n"
        "    print(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [\n"
        "        {'type': 'cryptographic-asset', 'bom-ref': 'k', 'name': 'key',\n"
        "         'cryptoProperties': {'assetType': 'related-crypto-material'}}]}))\n")
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    (tools_d / "printer.yaml").write_text(yaml.safe_dump({
        "id": "printer", "repo": None, "launcher": "local", "capture_stdout": True,
        "local": {"command": [sys.executable, str(script), "{language}", "{workdir}"]},
        "output": "out/printed.json", "languages": {"Python": "loud", "Go": "silent"}}))
    config = Config.defaults(tmp_path)
    config.data["tools"]["dir"] = str(tools_d)
    adapter = make_adapter(load_specs(config)["printer"], config)
    version = adapter.resolve()
    case = Case("Python", "Python", fixtures / "baseline-mini" / "Python", fixtures / "baseline-mini" / "Python" / "ground-truth.json", None, "crypto_showcase.py")
    work = tmp_path / "work"
    work.mkdir()
    res = adapter.run(case, work, version, tmp_path / "raw", tmp_path / "log.txt")
    assert res.status == "ok" and res.output_path == tmp_path / "raw" / "printed.json"
    assert json.loads(res.output_path.read_text())["components"][0]["name"] == "key"
    silent = Case("Go", "Go", case.dir, case.ground_truth, None, "main.go")
    res2 = adapter.run(silent, work, version, tmp_path / "raw2", tmp_path / "log.txt")
    assert res2.status == "failed" and res2.exit_code == 0 and res2.output_path is None
    assert any("nothing to stdout" in n for n in res2.notes)
    assert not (work / "out" / "printed.json").exists()      # the stale capture of the first run is gone too


def test_ok_exit_codes(tmp_path, fixtures):
    """A tool that exits 1 when it finds something: no "exited with 1" note once 1 is declared OK."""
    import sys
    import yaml
    script = tmp_path / "gate.py"
    script.write_text("import json, sys\n"
                      "json.dump({'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'components': [\n"
                      "    {'type': 'cryptographic-asset', 'bom-ref': 'm', 'name': 'MD5',\n"
                      "     'cryptoProperties': {'assetType': 'algorithm'}}]}, open(sys.argv[1], 'w'))\n"
                      "sys.exit(1)\n")
    tools_d = tmp_path / "tools.d"
    tools_d.mkdir()
    base = {"repo": None, "launcher": "local", "local": {"command": [sys.executable, str(script), "{output}"]},
            "output": "gate.json", "languages": {"*": "any"}}
    (tools_d / "strict.yaml").write_text(yaml.safe_dump({"id": "strict", **base}))
    (tools_d / "lenient.yaml").write_text(yaml.safe_dump({"id": "lenient", "ok_exit_codes": [0, 1], **base}))
    config = Config.defaults(tmp_path)
    config.data["tools"]["dir"] = str(tools_d)
    case = Case("Python", "Python", fixtures / "baseline-mini" / "Python", fixtures / "baseline-mini" / "Python" / "ground-truth.json", None, "crypto_showcase.py")
    for tool, expect_note in (("strict", True), ("lenient", False)):
        adapter = make_adapter(load_specs(config)[tool], config)
        work = tmp_path / tool
        work.mkdir()
        res = adapter.run(case, work, adapter.resolve(), tmp_path / "raw" / tool, tmp_path / "log.txt")
        assert res.status == "ok" and res.exit_code == 1
        assert any("exited with 1" in n for n in res.notes) is expect_note


def test_launcher_override_applies_where_the_tool_has_that_launcher():
    config = Config.defaults()
    specs = load_specs(config)
    for forced, expected in (("local", {"cbomkit": "docker", "cdxgen": "local", "cbomkit-theia": "local", "cryptoscan": "local"}),
                             ("docker", {"cbomkit": "docker", "cdxgen": "docker", "cbomkit-theia": "docker", "cryptoscan": "local"}),
                             (None, {"cbomkit": "docker", "cdxgen": "docker", "cbomkit-theia": "docker", "cryptoscan": "local"})):
        config.data["tools"]["default_launcher"] = forced
        assert {tid: make_adapter(specs[tid], config).launcher for tid in expected} == expected, forced
