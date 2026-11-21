"""Assign tool detections to ground-truth assets.

A detection is matched to a ground-truth asset of the same asset type when it is *compatible*
(same algorithm family, same material type, ...).  Among compatible assets the ones whose source
occurrences overlap the detection's reported locations win ("located" matches; a detection whose
occurrences span several assets credits each of them).  A detection without usable locations is
assigned to the single most similar asset.  Every pair records an *identity score* in [0, 1]
(matched slots minus conflicting slots over the asset's discriminating slots) so that a tool that
reports ``AES`` where the truth is ``AES-256-GCM`` is credited with a partial detection rather than
a miss plus a false positive.

Artifact cases (certificates, keys, keystores, configuration files) mark their occurrences
``fileLevel``: there a reported location that names the file is a hit even without a line, a file
holds several assets of one family, so only the best-scoring located candidates receive the
detection, and a detection pointing into an artifact file that holds no compatible asset is a false
positive rather than an imprecise location.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..baseline import GTAsset, GroundTruth, match_file, purl_key
from ..normalize.lexicon import EC_FAMILIES, hash_equal, padding_equal, param_equal, parse_name
from ..normalize.model import Detection
from ..normalize.x509 import dn_identifies, same_instant

MATERIAL_KEY_TYPES = {"private-key", "public-key", "secret-key", "key"}
# what a secret scanner calls a finding depends on the rule that fired ("generic-api-key" -> key), not on the value
SECRET_TYPES = {"password", "credential", "token", "key", "secret-key"}


@dataclass
class Pair:
    detection: Detection
    asset: GTAsset
    identity_score: float
    slots: dict                      # slot -> match | conflict | missing
    overlap: int                     # detection occurrences that hit an asset span
    located: bool
    level: str                       # oid | exact | partial | family | type | name
    ambiguous: bool = False

    def to_dict(self) -> dict:
        return {"detection": self.detection.ref, "asset": self.asset.id, "identityScore": round(self.identity_score, 4),
                "slots": self.slots, "overlap": self.overlap, "located": self.located, "level": self.level,
                "ambiguous": self.ambiguous}


@dataclass
class MatchResult:
    pairs: list = field(default_factory=list)                # list[Pair]
    unmatched: list = field(default_factory=list)            # list[Detection]
    unscored: list = field(default_factory=list)             # detections with an unknown asset type

    def pairs_for_asset(self, asset_id: str) -> list:
        return [p for p in self.pairs if p.asset.id == asset_id]

    def best_pair(self, asset_id: str) -> Optional[Pair]:
        ps = self.pairs_for_asset(asset_id)
        if not ps:
            return None
        return max(ps, key=lambda p: (p.identity_score, p.overlap, len([v for v in p.detection.attrs.values() if v is not None])))

    def matched_detection_refs(self) -> set:
        return {p.detection.ref for p in self.pairs}


# ----------------------------------------------------------------------------- locations
def overlap_detail(det: Detection, asset: GTAsset, tolerance: int) -> tuple[int, bool]:
    """(detection occurrences that hit one of the asset's spans, whether any hit was on a source line).

    A line hits a span within ``tolerance`` lines in the same file.  A span of file-level evidence is also
    hit by a location that names its file when either side has no line (tools report certificates and
    keys by path only; DER and keystores have no lines)."""
    spans = asset.spans()
    if not spans:
        return 0, False
    n = 0
    precise = False
    for occ in det.occurrences:
        if occ.line is None and not occ.file:
            continue
        lo = occ.line
        hi = occ.end_line or occ.line
        hit = False
        for f, s, e, file_level in spans:
            if occ.file and not match_file(occ.file, f):
                continue
            if lo is not None and s is not None:
                if lo <= e + tolerance and hi >= s - tolerance:
                    hit = True
                    if not file_level:
                        precise = True       # a source line; a PEM block holds a certificate and its algorithms
                        break
            elif file_level and occ.file:
                hit = True
        if hit:
            n += 1
    return n, precise


def overlap_count(det: Detection, asset: GTAsset, tolerance: int) -> int:
    return overlap_detail(det, asset, tolerance)[0]


def has_locations(det: Detection) -> bool:
    return any(o.line is not None or o.file for o in det.occurrences)


def in_artifact_file(det: Detection, gt: GroundTruth) -> bool:
    """The detection points into a file whose content is the evidence (artifact cases only)."""
    return bool(gt.artifact_files) and any(o.file and gt.is_artifact_file(o.file) for o in det.occurrences)


def _keep_located(located: list, score_of, precise_of) -> list:
    """Line-precise hits all receive the detection (one component may span several call sites); among hits
    that rest on file-level evidence only the best-scoring candidates do, because one artifact file holds
    many assets of the same family (a certificate's key and signature algorithms are both RSA)."""
    precise = [l for l in located if precise_of(l)]
    by_file = [l for l in located if not precise_of(l)]
    if by_file:
        top = max(score_of(l) for l in by_file)
        precise += [l for l in by_file if score_of(l) >= top - 1e-9]
    return precise


def _fallback(cands: list, det: Detection, gt: GroundTruth, implicit_of) -> list:
    """Candidates for an unlocated assignment.  A detection located in an artifact file that holds no
    compatible asset is wrong there; it can still be an asset that never has a location (implicit)."""
    if has_locations(det) and in_artifact_file(det, gt):
        return [c for c in cands if implicit_of(c)]
    return cands


# ----------------------------------------------------------------------------- lexical false positives
def is_lexical(det: Detection, gt: GroundTruth) -> bool:
    """True when the detection sits on a line the corpus marks as a non-asset mention of the same name."""
    mentions = gt.mention_lines()
    if not mentions:
        return False
    dn = _norm_name(det.name)
    fam = det.descriptor.family if det.descriptor else None
    for occ in det.occurrences:
        if occ.line is None or occ.line not in mentions:
            continue
        for m in mentions[occ.line]:
            where = m.file or gt.file
            if occ.file and where and not match_file(occ.file, where):
                continue
            mt = _norm_name(m.text)
            if mt and dn and (mt in dn or dn in mt):
                return True
            if fam and parse_name(m.text).family == fam:
                return True
    return False


# ----------------------------------------------------------------------------- algorithms
def family_compat(tool_family: Optional[str], gt_family: Optional[str]) -> Optional[float]:
    """1.0 same family, 0.5 generic EC vs a concrete EC family, None incompatible."""
    if not tool_family or not gt_family:
        return None
    if tool_family == gt_family:
        return 1.0
    if tool_family == "ec" and gt_family in EC_FAMILIES:
        return 0.5
    if gt_family == "ec" and tool_family in EC_FAMILIES:
        return 0.5
    return None


def slot_compare(det: Detection, asset: GTAsset) -> tuple[Optional[float], dict]:
    """Return (identity score, slot verdicts) or (None, {}) when the families are incompatible."""
    slots = asset.identity_slots
    d = det.descriptor
    if not slots or d is None:
        return None, {}
    fc = family_compat(d.family, slots.get("family"))
    if fc is None:
        return None, {}
    verdict = {"family": "match" if fc == 1.0 else "generic"}
    score = fc
    n = len(slots)
    for slot, expected in slots.items():
        if slot == "family":
            continue
        got = getattr(d, slot)
        if got in (None, ""):
            verdict[slot] = "missing"
            continue
        if slot == "param":
            ok = param_equal(got, expected)
        elif slot == "padding":
            ok = padding_equal(got, expected)
        elif slot == "hash":
            ok = hash_equal(got, expected)
        else:
            ok = str(got).lower() == str(expected).lower()
        if ok:
            verdict[slot] = "match"
            score += 1
        else:
            verdict[slot] = "conflict"
            score -= 1
    return max(0.0, score / n), verdict


def _level(score: float, verdict: dict, oid: bool) -> str:
    if oid:
        return "oid"
    if score >= 0.999:
        return "exact"
    if all(v == "match" for k, v in verdict.items() if k != "family") and verdict.get("family") == "match":
        return "exact"
    if len(verdict) == 1 or all(v == "missing" for k, v in verdict.items() if k != "family"):
        return "family"
    return "partial"


def _norm_name(s: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def match_algorithms(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("algorithm")
    oid_index: dict[str, list] = {}
    for a in assets:
        oid = a.props.get("oid")
        if oid:
            oid_index.setdefault(str(oid), []).append(a)
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        cands: list[tuple[GTAsset, float, dict, bool]] = []
        oid_hits = oid_index.get(det.oid or "", [])
        for a in assets:
            score, verdict = slot_compare(det, a)
            is_oid = a in oid_hits
            if is_oid and len(oid_hits) == 1:
                # the OID identifies the asset even if the name parses differently
                score = max(score if score is not None else 0.0, 1.0)
                verdict = verdict or {"family": "match"}
                verdict = {**verdict, "oid": "match"}
            elif is_oid:
                # an OID several assets share (rsaEncryption for every RSA key size) names the family only
                if score is None:
                    score, verdict = 1.0 / max(1, len(a.identity_slots)), {"family": "match"}
                verdict = {**verdict, "oid": "match"}
                is_oid = False
            if score is None:
                # last resort: the plain name equals the ground-truth name or id
                if det.descriptor is None or det.descriptor.family is None:
                    if _norm_name(det.name) and _norm_name(det.name) in (_norm_name(a.name), _norm_name(a.id)):
                        score, verdict = 1.0, {"name": "match"}
                if score is None:
                    continue
            cands.append((a, score, verdict, is_oid))
        if not cands:
            unmatched.append(det)
            continue
        located = []
        if has_locations(det):
            for a, score, verdict, is_oid in cands:
                ov, precise = overlap_detail(det, a, tolerance)
                if ov > 0:
                    located.append((a, score, verdict, is_oid, ov, precise))
        if located:
            for a, score, verdict, is_oid, ov, _ in _keep_located(located, lambda l: l[1], lambda l: l[5]):
                pairs.append(Pair(det, a, score, verdict, ov, True, _level(score, verdict, is_oid)))
            continue
        if has_locations(det) and is_lexical(det, gt):
            # located on a comment/string the corpus marks as a non-asset mention: a false positive
            unmatched.append(det)
            continue
        cands = _fallback(cands, det, gt, lambda c: c[0].implicit)
        if not cands:
            unmatched.append(det)
            continue
        # no located match: single best candidate by identity, prefer explicit (non-implicit) assets
        ranked = sorted(cands, key=lambda c: (c[1], c[3], not c[0].implicit, -len(c[0].identity_slots)), reverse=True)
        best = ranked[0]
        ambiguous = len(ranked) > 1 and (ranked[1][1], ranked[1][3], not ranked[1][0].implicit) == \
            (best[1], best[3], not best[0].implicit)
        if best[1] <= 0.0:
            unmatched.append(det)
            continue
        pairs.append(Pair(det, best[0], best[1], best[2], 0, False, _level(best[1], best[2], best[3]), ambiguous))
    return pairs, unmatched


# ----------------------------------------------------------------------------- materials
def _material_descriptor(det: Detection):
    ref = det.attrs.get("algorithmRef")
    props = det.attrs.get("algorithmRefProps")
    if not ref and not props:
        return None
    from ..normalize.lexicon import descriptor_from_fields
    return descriptor_from_fields(ref, props or {})


def referenced_algorithm_score(desc, gt_asset: Optional[GTAsset]) -> tuple[Optional[float], str]:
    """Score a referenced algorithm descriptor against the ground-truth algorithm asset it should name."""
    if desc is None or gt_asset is None:
        return None, "missing"
    fc = family_compat(desc.family, gt_asset.family)
    if fc is None:
        return None, "conflict"
    slots = gt_asset.identity_slots
    score = fc
    for slot, expected in slots.items():
        if slot == "family":
            continue
        got = getattr(desc, slot)
        if got in (None, ""):
            continue
        if slot == "param":
            ok = param_equal(got, expected)
        elif slot == "padding":
            ok = padding_equal(got, expected)
        elif slot == "hash":
            ok = hash_equal(got, expected)
        else:
            ok = str(got).lower() == str(expected).lower()
        score += 1 if ok else -1
    return max(0.0, min(1.0, score / max(1, len(slots)))), ("match" if fc == 1.0 else "generic")


def material_compat(det: Detection, asset: GTAsset) -> Optional[float]:
    t = det.attrs.get("type")
    g = asset.subtype
    if t is not None and t == g:
        return 1.0                     # includes "other" for objects CycloneDX has no type for (CSR, CRL)
    if t is None or t in ("unknown", "other"):
        return 0.25 if g else None
    if t == "key" and g in MATERIAL_KEY_TYPES:
        return 0.75
    if {t, g} <= {"nonce", "initialization-vector"}:
        return 0.75
    if {t, g} <= {"salt", "seed"} or {t, g} <= {"password", "credential"}:
        return 0.5
    if t in SECRET_TYPES and g in SECRET_TYPES:
        return SECRET_MISTYPED         # a secret, mistyped ("key" for a password found by a generic rule)
    return None


# Compatibility of a mistyped secret.  It only counts where the detection is located on the asset: an
# unlocated "token" is not evidence for a password somewhere else.
SECRET_MISTYPED = 0.2


def match_materials(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("related-crypto-material")
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        ref_desc = _material_descriptor(det)
        cands = []
        for a in assets:
            tc = material_compat(det, a)
            if tc is None or (tc == SECRET_MISTYPED and not overlap_count(det, a, tolerance)):
                continue
            verdict = {"type": "match" if tc == 1.0 else ("generic" if tc >= 0.5 else "missing")}
            score = tc
            n = 1
            if a.family:
                n += 1
                if ref_desc is None:
                    verdict["algorithm"] = "missing"
                else:
                    alg_score, alg_verdict = referenced_algorithm_score(ref_desc, gt.asset_by_id.get(a.algorithm_ref or ""))
                    if alg_score is None:
                        verdict["algorithm"] = "conflict"
                        score -= 1
                    else:
                        verdict["algorithm"] = alg_verdict
                        score += alg_score
            size = a.props.get("size")
            if size:
                n += 1
                got = det.attrs.get("size")
                if got is None:
                    verdict["size"] = "missing"
                elif int(got) == int(size) or int(got) * 8 == int(size):
                    verdict["size"] = "match"
                    score += 1
                else:
                    verdict["size"] = "conflict"
                    score -= 1
            cands.append((a, max(0.0, score / n), verdict))
        if not cands:
            unmatched.append(det)
            continue
        located = []
        if has_locations(det):
            for a, score, verdict in cands:
                ov = overlap_count(det, a, tolerance)
                if ov > 0:
                    located.append((a, score, verdict, ov))
        if located:
            # several candidates of the same type on the same lines: keep the best-scoring ones only
            top = max(l[1] for l in located)
            for a, score, verdict, ov in located:
                if score >= top - 1e-9:
                    pairs.append(Pair(det, a, score, verdict, ov, True,
                                      "exact" if score >= 0.999 else "partial"))
            continue
        cands = _fallback(cands, det, gt, lambda c: c[0].implicit)
        if not cands:
            unmatched.append(det)
            continue
        ranked = sorted(cands, key=lambda c: c[1], reverse=True)
        best = ranked[0]
        if best[1] <= 0.0:
            unmatched.append(det)
            continue
        ambiguous = len(ranked) > 1 and abs(ranked[1][1] - best[1]) < 1e-9
        pairs.append(Pair(det, best[0], best[1], best[2], 0, False, "exact" if best[1] >= 0.999 else "partial", ambiguous))
    return pairs, unmatched


# ----------------------------------------------------------------------------- certificates / protocols
def certificate_identity(det: Detection, asset: GTAsset) -> tuple[float, dict]:
    """Identity of a certificate detection: the type (1) plus every identifying attribute it reports
    (subject, issuer, validity) as +1 match / -1 conflict, over 1 + the number reported.  Attributes the
    tool leaves out do not count, so a bare "certificate here" keeps 1.0 and a single-certificate case
    scores as before; a CN-only subject identifies the certificate when the CN is right."""
    p = asset.props
    verdict = {"type": "match"}
    score, n = 1.0, 1
    for slot in ("subjectName", "issuerName"):
        expected = p.get(slot)
        if not expected or str(expected).startswith("runtime:"):
            continue
        ok = dn_identifies(det.attrs.get(slot), expected)
        if ok is None:
            continue
        n += 1
        score += 1 if ok else -1
        verdict[slot] = "match" if ok else "conflict"
    for slot in ("notValidBefore", "notValidAfter"):
        expected = p.get(slot)
        got = det.attrs.get(slot)
        if not expected or str(expected).startswith("runtime:") or not got:
            continue
        n += 1
        ok = same_instant(got, expected)
        score += 1 if ok else -1
        verdict[slot] = "match" if ok else "conflict"
    return max(0.0, score / n), verdict


def match_simple(gt: GroundTruth, detections: list, asset_type: str, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type(asset_type)
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        cands = []
        for a in assets:
            if asset_type == "certificate":
                score, verdict = certificate_identity(det, a)
                if score <= 0.0:
                    continue          # every identifying attribute it reports belongs to another certificate
            elif asset_type == "protocol":
                t = det.attrs.get("type")
                if t and a.subtype and t != a.subtype:
                    continue
                score = 1.0 if t else 0.5
                verdict = {"type": "match" if t else "missing"}
                v = det.attrs.get("version")
                gv = a.props.get("version")
                if gv:
                    if v is None:
                        verdict["version"] = "missing"
                        score = score / 2
                    elif _version_equal(v, gv):
                        verdict["version"] = "match"
                    else:
                        verdict["version"] = "conflict"
                        score = max(0.0, score - 0.5)
            else:
                score, verdict = 1.0, {"type": "match"}
            cands.append((a, score, verdict))
        if not cands:
            unmatched.append(det)
            continue
        located = [(a, s, v) + overlap_detail(det, a, tolerance) for a, s, v in cands]
        located = [l for l in located if l[3] > 0] if has_locations(det) else []
        if located:
            if asset_type == "certificate":
                # one component is one certificate: a bundle or keystore file holds several
                top = max(l[1] for l in located)
                located = [l for l in located if l[1] >= top - 1e-9]
            else:
                located = _keep_located(located, lambda l: l[1], lambda l: l[4])
            for a, s, v, ov, _ in located:
                pairs.append(Pair(det, a, s, v, ov, True, "exact" if s >= 0.999 else "partial"))
            continue
        cands = _fallback(cands, det, gt, lambda c: c[0].implicit)
        if not cands:
            unmatched.append(det)
            continue
        a, s, v = max(cands, key=lambda c: c[1])
        ambiguous = len(cands) > 1 if asset_type != "certificate" else \
            sum(1 for c in cands if abs(c[1] - s) < 1e-9) > 1
        pairs.append(Pair(det, a, s, v, 0, False, "exact" if s >= 0.999 else "partial", ambiguous))
    return pairs, unmatched


def _version_equal(a: str, b: str) -> bool:
    ra = re.search(r"\d+(\.\d+)*", str(a))
    rb = re.search(r"\d+(\.\d+)*", str(b))
    if not ra or not rb:
        return str(a).strip().lower() == str(b).strip().lower()
    return ra.group(0) == rb.group(0)


# ----------------------------------------------------------------------------- libraries
def _lib_names(asset: GTAsset) -> set[str]:
    names = {_norm_name(asset.name), _norm_name(asset.id.split(".", 1)[-1])}
    pk = purl_key(asset.props.get("purl"))
    if pk:
        names.add(_norm_name(pk.split("/")[-1]))
        names.add(_norm_name(pk))
    # "cryptography (pyca)" -> cryptography
    names.add(_norm_name(re.sub(r"\(.*?\)", "", asset.name)))
    return {n for n in names if n}


def match_libraries(gt: GroundTruth, detections: list, tolerance: int) -> tuple[list, list]:
    assets = gt.assets_of_type("library")
    pairs: list[Pair] = []
    unmatched: list[Detection] = []
    for det in detections:
        pk = purl_key(det.attrs.get("purl"))
        dn = _norm_name(det.name)
        dgn = _norm_name(f"{det.attrs.get('group') or ''}/{det.name}") if det.attrs.get("group") else None
        best = None
        for a in assets:
            apk = purl_key(a.props.get("purl"))
            score = 0.0
            if pk and apk and pk == apk:
                score = 1.0
            elif pk and apk and pk.split("/")[-1] == apk.split("/")[-1]:
                score = 0.9
            elif dn and dn in _lib_names(a):
                score = 0.8
            elif dgn and dgn in _lib_names(a):
                score = 0.8
            if score and (best is None or score > best[1]):
                best = (a, score)
        if best is None:
            unmatched.append(det)
            continue
        pairs.append(Pair(det, best[0], best[1], {"purl": "match" if best[1] == 1.0 else "name"}, 0, False,
                          "exact" if best[1] >= 0.999 else "name"))
    return pairs, unmatched


# ----------------------------------------------------------------------------- driver
def match_case(gt: GroundTruth, detections: list, tolerance: int = 1) -> MatchResult:
    result = MatchResult()
    by_type: dict[str, list] = {}
    for d in detections:
        by_type.setdefault(d.asset_type, []).append(d)
    for asset_type, dets in by_type.items():
        if asset_type == "algorithm":
            pairs, un = match_algorithms(gt, dets, tolerance)
        elif asset_type == "related-crypto-material":
            pairs, un = match_materials(gt, dets, tolerance)
        elif asset_type in ("certificate", "protocol"):
            pairs, un = match_simple(gt, dets, asset_type, tolerance)
        elif asset_type == "library":
            pairs, un = match_libraries(gt, dets, tolerance)
        else:
            result.unscored.extend(dets)
            continue
        result.pairs.extend(pairs)
        result.unmatched.extend(un)
    return result
