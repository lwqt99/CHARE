"""Copy only public replay inputs and the inherited backend to an isolated run.

The expected digest file remains in this parent verification process. The child
has no fixture generator, controller module, private scalars or expected hashes.
This process separation is an input discipline, not an OS security sandbox.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def unique_records(rows, field, label):
    if not isinstance(rows, list) or not rows:
        raise ValueError(label + " must be a nonempty list")
    ids = [row[field] for row in rows]
    if any(not isinstance(x, str) or not x for x in ids) or len(set(ids)) != len(ids):
        raise ValueError(label + " must have unique nonempty string IDs")
    return {row[field]: row for row in rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-dir", required=True)
    parser.add_argument("--manifest", default=str(ROOT / "DEPENDENCIES.json"))
    parser.add_argument("--evidence-dir", default=str(ROOT / "evidence"))
    args = parser.parse_args()
    evidence = Path(args.evidence_dir)
    expected = json.loads((evidence / "coordinate_expected_hashes.json").read_text())
    expected = unique_records(expected["expected"], "fixture_id", "Expected fixtures")
    inputs = json.loads((evidence / "coordinate_public_inputs.json").read_text())
    inputs = unique_records(inputs["fixtures"], "fixture_id", "Public fixtures")
    if set(inputs) != set(expected):
        raise ValueError("Public and expected fixture IDs differ")
    with tempfile.TemporaryDirectory(prefix="chare-public-replay-") as directory:
        temp = Path(directory)
        shutil.copy2(Path(__file__).with_name("public_replay.py"), temp / "public_replay.py")
        shutil.copy2(args.manifest, temp / "DEPENDENCIES.json")
        shutil.copy2(evidence / "coordinate_public_inputs.json", temp / "inputs.json")
        backend = temp / "backend"
        backend.mkdir()
        for name in ("type_a.py", "parameters.json"):
            shutil.copy2(Path(args.backend_dir) / name, backend / name)
        before = sorted(str(x.relative_to(temp)) for x in temp.rglob("*") if x.is_file())
        command = [sys.executable, "-I", str(temp / "public_replay.py"),
                   "--backend-dir", str(backend), "--manifest", str(temp / "DEPENDENCIES.json"),
                   "--inputs", str(temp / "inputs.json"), "--output", str(temp / "replayed.json")]
        child = subprocess.run(command, cwd=temp, check=True, capture_output=True, text=True,
                               env={"PATH": str(Path(sys.executable).parent), "PYTHONDONTWRITEBYTECODE": "1"})
        replay = json.loads((temp / "replayed.json").read_text())
    replay_records = unique_records(replay["results"], "fixture_id", "Replay results")
    if set(replay_records) != set(expected):
        raise ValueError("Replay did not return exactly the expected fixtures")
    checks = []
    for row in replay["results"]:
        exp = expected[row["fixture_id"]]
        recovered = row["recovery"]
        comparisons = {"original_GT_input_recovered": recovered["target_element_sha256"] == exp["target_element_sha256"],
                       "original_KDF_output_recovered": recovered["key_sha256"] == exp["key_sha256"],
                       "original_context_preserved": recovered["context_sha256"] == exp["context_sha256"],
                       "actual_core_point_isolated": recovered["isolated_core_point_sha256"] == exp["isolated_core_point_sha256"],
                       "wrong_context_changes_key": row["wrong_context"]["key_sha256"] != exp["key_sha256"],
                       "wrong_pad_fails_recovery": row["wrong_pad"]["target_element_sha256"] != exp["target_element_sha256"],
                       "missing_opening_rejected": row["missing_opening_rejected"]}
        if not all(comparisons.values()):
            raise AssertionError((row["fixture_id"], comparisons))
        checks.append({"fixture_id": row["fixture_id"], "status": "PASS", "checks": comparisons})
    result = {"status": "PASS", "schema": "chare.pending-opening.isolated-check.v1",
              "fixtures": len(checks), "checks_per_fixture": 7,
              "exact_nonempty_unique_fixture_coverage": True,
              "child_initial_files": before, "child_received_expected_hashes": False,
              "isolation_scope": "separate Python -I process and reduced input directory, not OS sandboxing",
              "checks": checks, "child_stdout": child.stdout.strip()}
    (evidence / "coordinate_replayed_hashes.json").write_text(json.dumps(replay, indent=2) + "\n")
    (evidence / "coordinate_isolated_check.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "fixtures": len(checks), "comparisons": len(checks) * 7}))


if __name__ == "__main__":
    main()
