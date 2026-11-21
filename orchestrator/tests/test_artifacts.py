"""The Artifacts case of the corpus (certificates, keys, keystores, configuration files): file-level
locations, certificate identity, shared OIDs, artifact-file false positives and the X.509 name/time
helpers.  Detections are shaped like CBOMKit-Theia's (common name only, path only) and CBOM-Lens'
(full RFC 2253 names, RFC 3339 times, path only)."""
import pytest

from orchestrator.baseline import GroundTruth
from orchestrator.evaluate.ledger import evaluate_case
from orchestrator.normalize import read_cbom
from orchestrator.normalize.x509 import dn_identifies, dn_similarity, parse_dn, parse_time, same_instant

from conftest import FIXTURES, cbom_doc

ART = FIXTURES / "baseline-artifacts" / "Artifacts"
ROOT_DN = "CN=CBOMFuse Test Root CA,O=CBOMFuse Baseline,C=CA"
ISSUING_DN = "CN=CBOMFuse Test Issuing CA,O=CBOMFuse Baseline,C=CA"


@pytest.fixture(scope="module")
def art_gt():
    return GroundTruth.load(ART / "ground-truth.json", "Artifacts")


def cert(ref, cn_or_dn, issuer, path, nb="2026-01-01T00:00:00Z", na=None, line=None):
    occ = {"location": path}
    if line:
        occ["line"] = line
    props = {"subjectName": cn_or_dn, "issuerName": issuer, "notValidBefore": nb, "certificateFormat": "X.509"}
    if na:
        props["notValidAfter"] = na
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": cn_or_dn,
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": props},
            "evidence": {"occurrences": [occ]}}


def alg(ref, name, path, oid=None, line=None, **ap):
    comp = {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap},
            "evidence": {"occurrences": [{"location": path, **({"line": line} if line else {})}]}}
    if oid:
        comp["cryptoProperties"]["oid"] = oid
    return comp


def mat(ref, name, mtype, path, line=None, alg_ref=None, size=None):
    mp = {"type": mtype}
    if alg_ref:
        mp["algorithmRef"] = alg_ref
    if size:
        mp["size"] = size
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": mp},
            "evidence": {"occurrences": [{"location": path, **({"line": line} if line else {})}]}}


def run(gt, *components):
    ev = evaluate_case(gt, read_cbom(cbom_doc(list(components))), "t", "1")
    rows = {r["assetId"]: r for r in ev.rows}
    return rows, ev.fp_rows, ev


def credited(rows, ref):
    return sorted(a for a, r in rows.items() if ref in r["detectionRefs"])


# ----------------------------------------------------------------------------- the reference CBOM
def test_reference_cbom_scores_perfectly(art_gt):
    from orchestrator.normalize import read_cbom_file
    ev = evaluate_case(art_gt, read_cbom_file(ART / "cbom.cdx.json"), "oracle", "ref")
    assert ev.stats["detectedAssets"] == ev.stats["assets"] == 64
    assert not ev.fp_rows
    for r in ev.rows:
        assert r["identityScore"] == 1.0 and r["completeness"] == 1.0 and r["correctness"] == 1.0, r["assetId"]
        assert not r["ambiguous"]
        if r["locations"]:
            assert r["locations"]["matched"] == r["locations"]["expected"], r["assetId"]


def test_ground_truth_model(art_gt):
    assert art_gt.file is None and art_gt.language == "Artifacts"
    assert "pki/server.crt" in art_gt.artifact_files and "examples/deploy-notes.md" in art_gt.artifact_files
    root = art_gt.asset_by_id["cert.root-ca"]
    files = {f for f, *_ in root.spans()}
    assert files == {"pki/root-ca.crt", "pki/ca-chain.pem", "pki/fullchain.p7b", "keystores/truststore.jks"}
    # binary artifacts have no lines but still count as places
    assert ("keystores/truststore.jks", None, None, True) in root.spans()
    assert all(m.file for m in art_gt.non_asset_mentions)


# ----------------------------------------------------------------------------- certificates
def test_cn_only_certificate_located_by_path(art_gt):
    """CBOMKit-Theia: subject/issuer are common names, the location is a path without a line."""
    rows, fps, _ = run(art_gt, cert("c1", "server.cbom-corpus.example", "CBOMFuse Test Issuing CA",
                                    "/scan/pki/server.crt", na="2028-01-01T00:00:00Z"))
    r = rows["cert.server"]
    assert r["detected"] and r["located"] and r["identityScore"] == 1.0 and not fps
    assert r["attributes"]["subjectName"]["correct"] == pytest.approx(1 / 3, abs=1e-3)
    assert r["attributes"]["issuerName"]["correct"] == pytest.approx(1 / 3, abs=1e-3)
    assert r["attributes"]["notValidBefore"]["correct"] == 1.0
    assert r["locations"] == {"expected": 2, "matched": 1, "reported": 1, "reportedMatched": 1}


def test_certificate_in_bundle_is_told_apart_by_subject(art_gt):
    rows, fps, _ = run(art_gt, cert("c1", "CBOMFuse Test Root CA", "CBOMFuse Test Root CA", "pki/ca-chain.pem"),
                       cert("c2", "CBOMFuse Test Issuing CA", "CBOMFuse Test Root CA", "pki/ca-chain.pem"))
    assert credited(rows, "c1") == ["cert.root-ca"] and credited(rows, "c2") == ["cert.issuing-ca"]
    assert not fps


def test_full_dn_in_any_spelling_is_correct(art_gt):
    """CBOM-Lens prints RFC 2253 names; OpenSSL and Java print them in other orders and spacings."""
    for subject in ("CN=api.cbom-corpus.example,O=CBOMFuse Baseline,C=CA",
                    "C = CA, O = CBOMFuse Baseline, CN = api.cbom-corpus.example",
                    "/C=CA/O=CBOMFuse Baseline/CN=api.cbom-corpus.example"):
        rows, fps, _ = run(art_gt, cert("c", subject, ISSUING_DN, "pki/api.der", nb="2026-01-01T00:00:00+00:00",
                                        na="2028-01-01 00:00:00"))
        r = rows["cert.api"]
        assert r["detected"] and not fps, subject
        assert r["correctness"] == 1.0 and r["attributes"]["subjectName"]["correct"] == 1.0, subject


def test_certificate_of_another_identity_is_a_false_positive(art_gt):
    rows, fps, _ = run(art_gt, cert("c", "www.example.org", "Some Other CA", "pki/server.crt"))
    assert not rows["cert.server"]["detected"] and [f["ref"] for f in fps] == ["c"]


def test_certificate_without_identifying_attributes_keeps_full_identity(python_gt):
    """Program cases: CryptoScan-style certificate findings carry no names and still score as in 1.0."""
    line = python_gt.asset_by_id["cert.self-signed"].locations()[0][1]
    comp = {"type": "cryptographic-asset", "bom-ref": "c", "name": "Self-Signed Certificate",
            "cryptoProperties": {"assetType": "certificate"},
            "evidence": {"occurrences": [{"location": "crypto_showcase.py", "line": line}]}}
    ev = evaluate_case(python_gt, read_cbom(cbom_doc([comp])), "t", "1")
    r = next(r for r in ev.rows if r["assetId"] == "cert.self-signed")
    assert r["detected"] and r["identityScore"] == 1.0 and r["located"]


# ----------------------------------------------------------------------------- algorithms
def test_bare_family_in_certificate_file_goes_to_the_best_candidate(art_gt):
    """root-ca.crt holds rsa-4096 (key) and sha256-with-rsa (signature): a bare "RSA" is the key."""
    rows, fps, _ = run(art_gt, alg("a", "RSA", "pki/root-ca.crt", oid="1.2.840.113549.1.1.1"),
                       alg("s", "SHA256-RSA", "pki/root-ca.crt", oid="1.2.840.113549.1.1.11", padding="pkcs1v15",
                           primitive="signature"))
    assert credited(rows, "a") == ["rsa-4096"]
    assert credited(rows, "s") == ["sha256-with-rsa"] and rows["sha256-with-rsa"]["matchLevel"] == "oid"
    assert not fps


def test_shared_oid_does_not_override_the_key_size(art_gt):
    """truststore.jks holds an RSA-4096 and an RSA-2048 key; rsaEncryption is the OID of both."""
    rows, fps, _ = run(art_gt, alg("k4", "RSA-4096", "keystores/truststore.jks", oid="1.2.840.113549.1.1.1"),
                       alg("k2", "RSA-2048", "keystores/truststore.jks", oid="1.2.840.113549.1.1.1"))
    assert credited(rows, "k4") == ["rsa-4096"] and credited(rows, "k2") == ["rsa-2048"]
    assert rows["rsa-4096"]["matchLevel"] == "exact" and not fps


def test_algorithm_in_artifact_file_where_it_does_not_occur_is_a_false_positive(art_gt):
    """aes-256-gcm is in the case (tls/openssl.cnf) but not in api.der: reporting it there is wrong, where
    a program case would hand an unlocated detection to its best candidate."""
    rows, fps, _ = run(art_gt, alg("x", "AES-256-GCM", "pki/api.der"))
    assert [f["ref"] for f in fps] == ["x"] and not rows["aes-256-gcm"]["detected"]
    # a wrong parameter on the right family is a correctness error, as on a source line
    rows, fps, _ = run(art_gt, alg("y", "SHA-256", "pki/api.der"))            # api.der is signed with SHA-384
    assert credited(rows, "y") == ["sha-384"] and rows["sha-384"]["matchLevel"] == "partial" and not fps


def test_implicit_asset_is_still_reachable_from_an_artifact_file(art_gt):
    rows, fps, _ = run(art_gt, alg("h", "SHA-512", "pki/device-ed25519.crt"))
    assert credited(rows, "h") == ["sha-512"] and rows["sha-512"]["implicit"] and not fps


def test_line_reporting_tool_hits_the_right_pem_block(art_gt):
    """CryptoScan-style: a line inside the second block of ca-chain.pem is the root CA."""
    rows, fps, _ = run(art_gt, cert("c", "CBOMFuse Test Root CA", "CBOMFuse Test Root CA", "pki/ca-chain.pem",
                                    line=28))
    assert credited(rows, "c") == ["cert.root-ca"]
    assert rows["cert.root-ca"]["locations"]["matched"] == 1


def test_lexical_mentions_are_per_file(art_gt):
    rows, fps, _ = run(art_gt, alg("m", "RSA", "examples/deploy-notes.md", line=16),
                       alg("n", "RSA", "pki/root-ca.crt", line=16))
    fp = {f["ref"]: f for f in fps}
    assert fp["m"]["lexical"] is True
    assert "n" not in fp and credited(rows, "n") == ["rsa-4096"]


# ----------------------------------------------------------------------------- related crypto material
def test_private_key_by_path_and_secret_scanner_line(art_gt):
    rows, fps, _ = run(art_gt, mat("p", "RSA-2048", "private-key", "pki/server.key", line=1, size=2048),
                       mat("q", "ECDSA", "private-key", "pki/api.key"))
    assert credited(rows, "p") == ["m.server-private-key"] and credited(rows, "q") == ["m.api-private-key"]
    assert rows["m.server-private-key"]["attributes"]["size"]["correct"] == 1.0 and not fps


def test_truncated_key_in_documentation_is_a_lexical_false_positive(art_gt):
    """gitleaks' private-key rule fires on a shortened key in a Markdown file; nothing is there."""
    _, fps, _ = run(art_gt, mat("leak", "private-key", "private-key", "examples/deploy-notes.md", line=10))
    assert [f["ref"] for f in fps] == ["leak"] and fps[0]["lexical"] is True


def test_csr_and_crl_match_as_other_material(art_gt):
    rows, fps, _ = run(art_gt,
                       alg("sig", "SHA256-RSA", "pki/server.csr", oid="1.2.840.113549.1.1.11", padding="pkcs1v15"),
                       mat("csr", "CSR: server.cbom-corpus.example", "other", "pki/server.csr", alg_ref="sig"),
                       mat("crl", "CRL: CBOMFuse Test Issuing CA", "other", "pki/issuing-ca.crl"))
    assert credited(rows, "csr") == ["m.server-csr"] and rows["m.server-csr"]["matchLevel"] == "exact"
    assert credited(rows, "crl") == ["m.issuing-ca-crl"] and not fps


def test_mistyped_secret_counts_only_where_it_is_located(art_gt):
    """Without a path, gitleaks' generic rule calls the Terraform password a "key" (CBOM-Lens)."""
    rows, fps, _ = run(art_gt, mat("g", "generic-api-key", "key", "secrets/main.tf", line=7))
    r = rows["m.db-password"]
    assert credited(rows, "g") == ["m.db-password"] and r["attributes"]["type"]["correct"] == 0.0 and not fps
    rows, fps, _ = run(art_gt, mat("g", "generic-api-key", "key", "secrets/main.tf", line=3))
    assert [f["ref"] for f in fps] == ["g"]


def test_jwt_and_signing_key(art_gt):
    rows, fps, _ = run(art_gt, mat("t", "jwt", "token", "secrets/app.env", line=6),
                       mat("k", "generic-api-key", "key", "secrets/app.env", line=5))
    assert credited(rows, "t") == ["m.service-token"] and rows["m.service-token"]["matchLevel"] == "partial"
    assert credited(rows, "k") == ["m.jwt-signing-key"] and not fps


# ----------------------------------------------------------------------------- protocol
def test_openssl_cnf_protocol(art_gt):
    comp = {"type": "cryptographic-asset", "bom-ref": "p", "name": "TLSv1.3",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                "type": "tls", "version": "1.3",
                "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}, {"name": "TLS_CHACHA20_POLY1305_SHA256"}]}},
            "evidence": {"occurrences": [{"location": "tls/openssl.cnf"}]}}
    rows, fps, _ = run(art_gt, comp)
    r = rows["tls13-openssl"]
    assert r["detected"] and r["correctness"] == 1.0 and not fps


# ----------------------------------------------------------------------------- helpers
def test_parse_dn_spellings():
    want = frozenset({("cn", "a b"), ("o", "x, inc"), ("c", "ca")})
    assert parse_dn("CN=a b,O=x\\, Inc,C=CA") == want
    assert parse_dn("C = CA, O = \"x, Inc\", CN = a b") is None           # unescaped comma: unreadable
    assert parse_dn("/C=CA/O=x, Inc/CN=a b") == want
    assert parse_dn("commonName=a b+organizationName=x\\2C Inc,countryName=CA") == want
    assert parse_dn("a b") == frozenset({("cn", "a b")})


def test_dn_similarity_and_identity():
    full = "CN=svc,OU=Service Accounts,O=CBOMFuse Baseline,C=CA"
    assert dn_similarity("C=CA, O=CBOMFuse Baseline, OU=Service Accounts, CN=svc", full) == 1.0
    assert dn_similarity("svc", full) == pytest.approx(0.25)
    assert dn_similarity(None, full) == 0.0
    assert dn_identifies("svc", full) is True
    assert dn_identifies("CN=other", full) is False
    assert dn_identifies("O=CBOMFuse Baseline", full) is None
    assert dn_identifies(None, full) is None
    assert dn_identifies("CN=svc,O=Elsewhere", full) is False


def test_time_parsing():
    t = parse_time("2026-01-01T00:00:00Z")
    for s in ("2026-01-01T00:00:00+00:00", "2026-01-01 00:00:00", "2025-12-31T16:00:00-08:00",
              "20260101000000Z", "260101000000Z", "2026-01-01T00:00:00.000Z", "Jan  1 00:00:00 2026 GMT"):
        assert parse_time(s) == t, s
    assert same_instant("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00")
    assert not same_instant("2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z")
    assert parse_time("not a date") is None and not same_instant("x", "y")
