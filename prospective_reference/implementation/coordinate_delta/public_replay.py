"""Replay the new pending-opening recovery using public curve coordinates only.

The expected original key, fixture generator and secret values are NOT inputs.
Run with Python 3.10+ and the hash-pinned prior Type-A backend. This reference
KDF checks context binding; it is not the original Go/PBC implementation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_backend(directory, manifest):
    directory = Path(directory).resolve()
    for name, expected in manifest["files"].items():
        actual = sha((directory / name).read_bytes())
        if actual != expected:
            raise ValueError("Inherited backend dependency hash mismatch: " + name)
    spec = importlib.util.spec_from_file_location("chare_prior_type_a", directory / "type_a.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.TypeA(directory / "parameters.json")


def decode(b, record):
    # Route through the inherited canonical decoder and actual subgroup check.
    if record == {"infinity": True}:
        raw = bytes(1 + 2 * b.width)
    else:
        if set(record) != {"x", "y"}:
            raise ValueError("Invalid public point record")
        raw = b"\x04" + int(record["x"]).to_bytes(b.width, "big") + int(record["y"]).to_bytes(b.width, "big")
    return b.decode_point(raw)


def kdf(b, context, element):
    prefix = b"CHARE-coordinate-reference-H_K\0"
    return hashlib.sha256(prefix + len(context).to_bytes(8, "big") +
                          context + b.encode_gt(element)).digest()


def recover(b, fixture, context_override=None, opening_override=None):
    opening = fixture.get("opening") if opening_override is None else opening_override
    if not opening or "point" not in opening:
        raise ValueError("An actual public pad-opening point is required")
    public, target = fixture["public"], fixture["target"]
    h, gamma = decode(b, public["h"]), decode(b, public["Gamma"])
    contribution = decode(b, fixture["first_contribution"]["point"])
    pad = decode(b, opening["point"])
    core_point = b.add(contribution, b.neg(pad))
    q, r = b.neg(h), b.add(gamma, core_point)
    c0, c1 = decode(b, target["C0"]), decode(b, target["C1"])
    recovered = b.fm(b.pair(c0, r), b.pair(c1, q))
    context = canonical(target["original_context"] if context_override is None else context_override)
    key = kdf(b, context, recovered)
    return {"target_element_sha256": sha(b.encode_gt(recovered)),
            "key_sha256": sha(key),
            "context_sha256": sha(context),
            "isolated_core_point_sha256": sha(b.encode_point(core_point))}


def replay_all(b, bundle):
    fixtures = bundle.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError("A nonempty public fixture list is required")
    ids = [x["fixture_id"] for x in fixtures]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate public fixture IDs")
    outputs = []
    for fixture in fixtures:
        result = recover(b, fixture)
        wrong_context = dict(fixture["target"]["original_context"])
        wrong_context["snapshot_id"] = wrong_context["snapshot_id"] + "/different"
        altered = recover(b, fixture, context_override=wrong_context)
        # A public additive offset of the real opening is the wrong-point control.
        wrong_pad = recover(b, fixture, opening_override=fixture["negative_control_opening"])
        missing = dict(fixture)
        missing.pop("opening")
        try:
            recover(b, missing)
        except ValueError:
            missing_rejected = True
        else:
            missing_rejected = False
        outputs.append({"fixture_id": fixture["fixture_id"], "recovery": result,
                        "wrong_context": altered, "wrong_pad": wrong_pad,
                        "missing_opening_rejected": missing_rejected,
                        "input_scope": "public points; original public context; no expected key or source scalar"})
    return {"schema": "chare.pending-opening.public-replay.v1", "results": outputs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text())
    bundle = json.loads(Path(args.inputs).read_text())
    b = load_backend(args.backend_dir, manifest)
    result = replay_all(b, bundle)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "REPLAYED", "fixtures": len(result["results"]),
                      "output": str(Path(args.output))}))


if __name__ == "__main__":
    main()
