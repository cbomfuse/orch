"""Normalisation of X.509 distinguished names and validity times as tools report them.

Tools disagree on how to print a name: ``CN=a,O=b,C=CA`` (RFC 4514, most specific first), ``C = CA, O = b,
CN = a`` (OpenSSL), ``/C=CA/O=b/CN=a`` (OpenSSL one-line), ``CN=a, O=b, C=CA`` (Java), or just the common
name ``a`` (CBOMKit-Theia).  Validity times arrive as RFC 3339 with ``Z`` or an offset, with a space instead
of the ``T``, or as ASN.1 ``UTCTime``/``GeneralizedTime``.  These helpers compare by content, not by spelling.
"""
from __future__ import annotations

import datetime
import re
from typing import Optional

_ATTR = {
    "cn": "cn", "commonname": "cn", "2.5.4.3": "cn",
    "o": "o", "organizationname": "o", "2.5.4.10": "o",
    "ou": "ou", "organizationalunitname": "ou", "2.5.4.11": "ou",
    "c": "c", "countryname": "c", "2.5.4.6": "c",
    "l": "l", "localityname": "l", "2.5.4.7": "l",
    "st": "st", "s": "st", "stateorprovincename": "st", "2.5.4.8": "st",
    "street": "street", "streetaddress": "street", "2.5.4.9": "street",
    "dc": "dc", "domaincomponent": "dc", "0.9.2342.19200300.100.1.25": "dc",
    "uid": "uid", "userid": "uid", "0.9.2342.19200300.100.1.1": "uid",
    "e": "email", "email": "email", "emailaddress": "email", "1.2.840.113549.1.9.1": "email",
    "serialnumber": "serialnumber", "2.5.4.5": "serialnumber",
    "title": "title", "2.5.4.12": "title", "givenname": "givenname", "gn": "givenname", "2.5.4.42": "givenname",
    "sn": "surname", "surname": "surname", "2.5.4.4": "surname",
}
_SPLIT_RE = re.compile(r"(?<!\\)[,;+]")


def _unescape(v: str) -> str:
    v = re.sub(r"\\([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), v)
    v = re.sub(r"\\(.)", r"\1", v)
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    return v


def parse_dn(text: Optional[str]) -> Optional[frozenset]:
    """The set of (attribute, value) pairs of a printed DN; a bare value is taken as the common name.
    ``None`` when the text cannot be read as a name."""
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    if "=" not in s:
        return frozenset({("cn", re.sub(r"\s+", " ", s).lower())})
    parts = [p for p in s.split("/") if p] if s.startswith("/") else _SPLIT_RE.split(s)
    out = set()
    for part in parts:
        if "=" not in part:
            return None                        # an unescaped separator inside a value: not parseable
        k, v = part.split("=", 1)
        key = _ATTR.get(re.sub(r"[\s_-]", "", k).lower())
        if key is None:
            key = k.strip().lower()
        out.add((key, re.sub(r"\s+", " ", _unescape(v.strip())).lower()))
    return frozenset(out)


def dn_similarity(reported: Optional[str], expected: Optional[str]) -> float:
    """Jaccard index of the attribute/value pairs (order and spelling do not matter): a tool that reports only
    the common name of ``CN=a,O=b,C=CA`` scores 1/3.  Unparseable names fall back to a whitespace- and
    case-insensitive string comparison."""
    r, e = parse_dn(reported), parse_dn(expected)
    if r is None or e is None:
        norm = lambda s: re.sub(r"\s+", "", s or "").lower()  # noqa: E731
        return 1.0 if reported and norm(reported) == norm(expected) else 0.0
    if not r or not e:
        return 0.0
    return len(r & e) / len(r | e)


def dn_identifies(reported: Optional[str], expected: Optional[str]) -> Optional[bool]:
    """Whether a reported name designates the expected one: True when every pair it states is right and it
    states the common name (a CN-only report identifies a certificate), False on any wrong pair, None when
    nothing was reported."""
    if not reported:
        return None
    r, e = parse_dn(reported), parse_dn(expected)
    if r is None or e is None:
        return dn_similarity(reported, expected) == 1.0
    if not r <= e:
        return False
    if r == e or any(k == "cn" for k, _ in r):
        return True
    return None                                # right but too partial (no CN) to tell certificates apart


_TIME_FORMATS = ("%Y%m%d%H%M%SZ", "%y%m%d%H%M%SZ", "%Y%m%d%H%M%S%z", "%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y")


def parse_time(text: Optional[str]) -> Optional[datetime.datetime]:
    """An aware UTC datetime for RFC 3339 / ISO 8601 (``Z``, offsets, space separator, fractions) and ASN.1
    time strings; naive values are taken as UTC."""
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    iso = s.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s) else s
    iso = re.sub(r"[zZ]$", "+00:00", iso)
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    dt = None
    try:
        dt = datetime.datetime.fromisoformat(iso)
    except ValueError:
        for fmt in _TIME_FORMATS:
            try:
                dt = datetime.datetime.strptime(re.sub(r"\s+", " ", s), fmt)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def same_instant(reported: Optional[str], expected: Optional[str]) -> bool:
    a, b = parse_time(reported), parse_time(expected)
    if a is not None and b is not None:
        return a == b
    return bool(reported) and str(reported).strip() == str(expected).strip()
