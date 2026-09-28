"""RFC 8785 JSON Canonicalization Scheme (JCS).

Produces the single byte representation of a JSON value that is signed and
hashed everywhere in POLARYS.  Supported values: dict (str keys), list, str,
int, float, bool and None.  Integers outside the IEEE-754 safe range are
rejected because JCS serialises every number as a double and would silently
lose precision; carry such values as strings instead.
"""

from __future__ import annotations

import json
import math
from typing import Any

MAX_SAFE_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of ``value``."""
    return _ser(value).encode("utf-8")


def _ser(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise CanonicalizationError(f"integer {v} exceeds 2^53-1; encode it as a string")
        return str(v)
    if isinstance(v, float):
        return _number(v)
    if isinstance(v, str):
        # json.dumps escapes exactly what JCS requires (", \, control chars,
        # with the short forms \b \f \n \r \t and lowercase \u00xx otherwise).
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_ser(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(k).__name__}")
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _ser(v[k]) for k in keys) + "}"
    raise CanonicalizationError(f"unsupported type {type(v).__name__}")


def _number(x: float) -> str:
    """ECMAScript Number.prototype.toString, as required by RFC 8785 section 3.2.2.3."""
    if not math.isfinite(x):
        raise CanonicalizationError("NaN and Infinity are not valid JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    mant, _, e = repr(abs(x)).partition("e")
    exp = int(e) if e else 0
    ip, _, fp = mant.partition(".")
    ip_s = ip.lstrip("0")
    if ip_s:
        n = len(ip_s) + exp
    else:
        n = exp - (len(fp) - len(fp.lstrip("0")))
    s = (ip + fp).lstrip("0").rstrip("0")
    k = len(s)
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        e2 = n - 1
        es = ("+" if e2 >= 0 else "-") + str(abs(e2))
        out = (s if k == 1 else s[0] + "." + s[1:]) + "e" + es
    return sign + out
