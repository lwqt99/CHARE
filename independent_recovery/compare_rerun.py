#!/usr/bin/env python3
"""Compare the R2 reference and its R3 rerun without copying execution state.

Every listed file must match byte for byte. No timing field, seed, scalar, or
other content is removed before comparison. Reports contain only hashes,
lengths, equality flags, and the paths of mismatches, never mismatched values.
"""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUTS = (
    "parameters.json",
    "public_recovery_inputs.json",
    "expected_recovery_hashes.json",
    "backend_selftest.json",
    "isolated_public_replay.json",
    "execution_results.json",
)
SOURCES = ("type_a.py", "recovery_compiler.py", "run_traces.py", "replay_public.py")


def differences(left, right, path="$", found=None):
    """Return differing JSON paths only; no source values enter the report."""
    if found is None:
        found = []
    if type(left) is not type(right):
        found.append(path + " (type)")
    elif isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            child = path + "[" + json.dumps(key, ensure_ascii=True) + "]"
            if key not in left or key not in right:
                found.append(child + " (missing)")
            else:
                differences(left[key], right[key], child, found)
    elif isinstance(left, list):
        if len(left) != len(right):
            found.append(path + " (length)")
        for index, (a, b) in enumerate(zip(left, right)):
            differences(a, b, path + "[" + str(index) + "]", found)
    elif left != right:
        found.append(path)
    return found


def compare_file(name, original_dir, rerun_dir, category):
    left_path, right_path = original_dir / name, rerun_dir / name
    record = {"file": name, "category": category}
    if not left_path.is_file() or not right_path.is_file():
        record.update(status="FAIL", original_exists=left_path.is_file(),
                      rerun_exists=right_path.is_file())
        return record
    left, right = left_path.read_bytes(), right_path.read_bytes()
    record.update(
        original_bytes=len(left), rerun_bytes=len(right),
        original_sha256=hashlib.sha256(left).hexdigest(),
        rerun_sha256=hashlib.sha256(right).hexdigest(),
        bytes_identical=left == right,
        status="PASS" if left == right else "FAIL",
    )
    if name.endswith(".json"):
        try:
            a, b = json.loads(left), json.loads(right)
            paths = differences(a, b)
            record.update(json_identical=a == b,
                          differing_json_path_count=len(paths),
                          differing_json_paths=paths[:100],
                          differing_paths_truncated=len(paths) > 100)
        except (UnicodeError, ValueError) as error:
            record.update(status="FAIL", json_error=type(error).__name__)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-dir", required=True, type=Path,
                        help="Original R2 verification/coordinate_pairing directory")
    parser.add_argument("--rerun-dir", required=True, type=Path,
                        help="R3 reference_rerun directory")
    parser.add_argument("--output", type=Path, default=HERE / "rerun_comparison.json")
    args = parser.parse_args()
    records = [compare_file(name, args.original_dir, args.rerun_dir, "stable_output")
               for name in OUTPUTS]
    records += [compare_file(name, args.original_dir, args.rerun_dir, "reference_source")
                for name in SOURCES]
    passed = all(record["status"] == "PASS" for record in records)
    result = {
        "schema_version": 1,
        "status": "PASS" if passed else "FAIL",
        "scope": "Exact comparison of the R2 Python reference and its R3 rerun using the same fixtures",
        "original_dir": str(args.original_dir),
        "rerun_dir": str(args.rerun_dir),
        "normalization_applied": False,
        "ignored_json_fields": [],
        "timing_exclusions": [],
        "required_stable_outputs": list(OUTPUTS),
        "required_reference_sources": list(SOURCES),
        "files": records,
        "summary": {
            "stable_outputs_compared": len(OUTPUTS),
            "reference_sources_compared": len(SOURCES),
            "byte_identical_files": sum(record.get("bytes_identical", False) for record in records),
            "failed_files": [record["file"] for record in records if record["status"] != "PASS"],
        },
        "limitations": [
            "This is a same-code, same-fixture rerun comparison, not an independent trace implementation.",
            "This report contains no copied execution state, actor seeds, or private scalar values.",
            "This comparison does not reproduce native Go/PBC measurements.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], **result["summary"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
