"""One command to verify an assembled CHARE reference evidence module."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest(root):
    count = 0
    for line in (root / "MANIFEST.sha256").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        p = Path(relative)
        if p.is_absolute() or ".." in p.parts or sha(root / p) != expected:
            raise ValueError("Packaged file integrity mismatch: " + relative)
        count += 1
    if not count:
        raise ValueError("Empty module manifest")
    return count


def main():
    root = Path(__file__).resolve().parent
    count = check_manifest(root)
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    commands = [
        [sys.executable, str(root / "implementation/controller/run_checks.py")],
        [sys.executable, str(root / "implementation/coordinate_delta/verify_isolated.py"),
         "--backend-dir", str(root / "vendor/coordinate_reference"),
         "--manifest", str(root / "DEPENDENCIES.json"), "--evidence-dir", str(root / "evidence")],
    ]
    logs = []
    for command in commands:
        result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
        logs.append({"entrypoint": str(Path(command[1]).relative_to(root)),
                     "exit_code": result.returncode, "stdout": result.stdout.strip()})
        if result.returncode:
            raise RuntimeError("Reference check failed: " + logs[-1]["entrypoint"] + "\n" + result.stderr)
    controller = json.loads((root / "implementation/controller/controller_summary.json").read_text())
    replay = json.loads((root / "evidence/coordinate_isolated_check.json").read_text())
    if not (controller["status"] == replay["status"] == "PASS" and controller["case_count"] == 10
            and replay["fixtures"] == 2 and replay["exact_nonempty_unique_fixture_coverage"]
            and replay["child_received_expected_hashes"] is False):
        raise AssertionError("Expected reference coverage was not obtained")
    # The deterministic controller regenerates its evidence. Verify that it
    # still matches the original manifest; newly written isolated outputs are
    # not part of that input manifest.
    check_manifest(root)
    record = {"schema": "chare.reference.integration.v1", "status": "PASS",
              "round": "CHARE-C20261115-03", "purpose": "portable assembly and claim-evidence integration",
              "input_manifest_entries_checked": count, "controller_groups": controller["case_count"],
              "coordinate_fixtures_replayed": replay["fixtures"],
              "coordinate_comparisons": replay["fixtures"] * replay["checks_per_fixture"],
              "new_scientific_fixture_count": 0, "original_go_measurements_rerun": False,
              "independent_directory": True, "entrypoint_results": logs,
              "prior_assembly_sha256": sha(root / "ASSEMBLY.json")}
    (root / "INTEGRATION_RESULT.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "controller_groups": 10, "public_fixtures_replayed": 2,
                      "new_scientific_fixtures": 0, "result": "INTEGRATION_RESULT.json"}))


if __name__ == "__main__":
    main()
