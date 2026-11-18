"""Recheck returned Type-A arithmetic; no curve-strength claim or measurements."""
from pathlib import Path
import hashlib
import re

VERSION = "pbc-type-a-return-audit-v1"
EXPECTED = {
    "profile": "pbc-type-a-admission-v1", "before_native_parser": True,
    "strict_fields": True, "solinas_identity": True, "cofactor_identity": True,
    "cofactor_multiple_of_12": True, "probable_prime_rounds": 64,
    "max_integer_bits": 16384, "security_strength_certified": False,
}


def audit_parameters(run, manifest):
    if manifest.get("implementation_version") not in {"chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
        return {"status": "legacy_not_certified", "scope": "Earlier parameter admission was narrower; not retroactively upgraded."}
    raw = (Path(run) / "parameters.txt").read_bytes()
    if not 0 < len(raw) <= 1 << 20 or any(c not in (9, 10, 13) and not 32 <= c <= 126 for c in raw):
        raise ValueError("Invalid Type-A byte profile")
    fields = {}
    allowed = {"type", "q", "h", "r", "exp1", "exp2", "sign1", "sign0"}
    for line in raw.decode("ascii").splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 2 or parts[0] not in allowed or parts[0] in fields:
            raise ValueError("Malformed, duplicate or unknown Type-A field")
        fields[parts[0]] = parts[1]
    if set(fields) != allowed or fields["type"] != "a":
        raise ValueError("Incomplete Type-A parameters")
    v = {}
    for name in ("q", "h", "r", "exp1", "exp2"):
        value = fields[name]
        if len(value) > 5000 or re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise ValueError("Noncanonical Type-A integer")
        # Parse in bounded chunks, independent of Python's decimal digit limit.
        number = 0
        for start in range(0, len(value), 1000):
            piece = value[start:start + 1000]
            number = number * 10**len(piece) + int(piece)
        if number.bit_length() > 16384:
            raise ValueError("Oversized Type-A integer")
        v[name] = number
    for name in ("sign1", "sign0"):
        if fields[name] not in {"1", "-1"}:
            raise ValueError("Invalid Solinas sign")
        v[name] = int(fields[name])
    if not 0 < v["exp1"] < v["exp2"] <= 16384 or not 3 < v["r"] < v["q"]:
        raise ValueError("Type-A range mismatch")
    if (1 << v["exp2"]) + v["sign1"] * (1 << v["exp1"]) + v["sign0"] != v["r"]:
        raise ValueError("Type-A Solinas identity mismatch")
    if v["h"] * v["r"] != v["q"] + 1 or v["h"] % 12:
        raise ValueError("Type-A cofactor identity/profile mismatch")
    info = manifest.get("parameters", {})
    report = info.get("admission")
    if report != EXPECTED or any(type(report[k]) is not type(x) for k, x in EXPECTED.items()):
        raise ValueError("Missing or inconsistent native parameter-admission report")
    if info.get("type") != "a" or info.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError("Parameter identity mismatch")
    if info.get("r_bits_actual") != v["r"].bit_length() or info.get("q_bits_actual") != v["q"].bit_length():
        raise ValueError("Parameter bit count mismatch")
    for n in manifest["configuration"]["capacities"]:
        if type(n) is not int or n < 2 or v["r"] <= n + 1:
            raise ValueError("Parameter/capacity bound mismatch")
    return {"status": "arithmetic_rechecked", "version": VERSION,
            "scope": "Exact identities rechecked against original bytes; Go probable-prime result reported, not independently certified; no concrete security-bit calibration."}
