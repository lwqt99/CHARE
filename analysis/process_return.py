"""Import an actual Go/PBC return ZIP, audit it, and run existing analysis tools.

No measurements are generated here. Each import gets a new directory; previous
imports and the original archive are never overwritten.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
MAX_FILES = 100_000
MAX_UNPACKED_BYTES = 8 * 1024**3
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10))}


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_parts(name):
    """Accept portable, canonical relative ZIP paths only."""
    parts = name.split("/")
    if not name or any(c in name for c in '\\:<>"|?*') or any(ord(c) < 32 for c in name):
        raise ValueError(f"Invalid archive path: {name!r}")
    if any(p in {"", ".", ".."} or p.endswith((" ", ".")) or
           p.split(".")[0].upper() in RESERVED for p in parts):
        raise ValueError(f"Noncanonical archive path: {name!r}")
    return parts


def extract_verified(archive, checksum, destination):
    """Check the outer digest, extract regular files, then check complete coverage."""
    archive, checksum, destination = map(Path, (archive, checksum, destination))
    line = checksum.read_text(encoding="utf-8-sig").strip()
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:[ \t]+\*?([^\r\n]+))?", line)
    if not match or (match[2] is not None and match[2] != archive.name):
        raise ValueError("Expected the original ZIP and its matching one-line .sha256 file")
    digest = sha256_file(archive)
    if digest != match[1].lower():
        raise ValueError("ZIP SHA-256 mismatch; analysis was not started")
    if destination.exists():
        raise FileExistsError("Import destination already exists; refusing to overwrite")

    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > MAX_FILES or sum(e.file_size for e in entries) > MAX_UNPACKED_BYTES:
            raise ValueError("Archive exceeds import limits: 100,000 entries / 8 GiB unpacked")
        seen, files = set(), set()
        for entry in entries:
            if entry.orig_filename != entry.filename:
                raise ValueError("Archive entry requires implicit path normalization")
            name = entry.filename[:-1] if entry.is_dir() else entry.filename
            safe_parts(name)
            if name.casefold() in seen:
                raise ValueError(f"Duplicate/case-colliding archive path: {name}")
            seen.add(name.casefold())
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR} or entry.flag_bits & 1:
                raise ValueError("Links, special files and encrypted entries are not supported")
            if not entry.is_dir():
                files.add(name)
        if "SHA256SUMS" not in files or "manifest.json" not in files:
            raise ValueError("Use the original runner return.zip, without a wrapping folder")
        destination.mkdir(parents=True)
        for entry in entries:
            if entry.is_dir():
                continue
            target = destination.joinpath(*safe_parts(entry.filename))
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("Archive path leaves the import directory")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)

    listed = set()
    for row in (destination / "SHA256SUMS").read_text(encoding="utf-8-sig").splitlines():
        expected, name = row.split("  ", 1)
        safe_parts(name)
        if name in listed or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            raise ValueError("Invalid or duplicate inner checksum entry")
        if name not in files or sha256_file(destination.joinpath(*safe_parts(name))) != expected.lower():
            raise ValueError(f"Inner checksum mismatch: {name}")
        listed.add(name)
    if listed != files - {"SHA256SUMS"}:
        raise ValueError("Inner checksum list must cover every returned file exactly once")
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Original return.zip from the VM")
    parser.add_argument("--checksum", type=Path, help="Defaults to <archive>.sha256")
    parser.add_argument("--output", type=Path, default=HERE / "output" / "imports")
    parser.add_argument("--note", default="", help="Optional visible scope label for plots")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify-only", action="store_true", help="Audit without tables or figures")
    modes.add_argument("--skip-plots", action="store_true", help="Audit and tables without Matplotlib")
    args = parser.parse_args()
    archive = args.archive.resolve()
    checksum = (args.checksum or Path(str(archive) + ".sha256")).resolve()
    identity = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:8]
    delivery = args.output.resolve() / identity
    delivery.mkdir(parents=True, exist_ok=False)
    run = delivery / "run"
    receipt = {"status": "started", "archive": str(archive), "checksum": str(checksum),
               "input_directory": str(run), "generated_at_utc": identity,
               "mode": "verify_only" if args.verify_only else "tables_only" if args.skip_plots else "tables_and_figures",
               "scope": "Transport/data consistency only, not experimental authenticity or a security proof.",
               "scripts": {n: sha256_file(HERE / n) for n in
                           ("process_return.py", "summarize_workload.py", "cold_audit_accounting.py", "transport_accounting.py", "parameter_accounting.py", "plot_results.py")}}
    try:
        receipt["archive_sha256"] = extract_verified(archive, checksum, run)
        from summarize_workload import audit_input
        kept, states, manifest, provenance = audit_input(run)
        receipt.update(run_id=manifest["run_id"], implementation_version=manifest["implementation_version"],
                       case_statuses={k: v["status"] for k, v in states.items()},
                       accepted_measurement_rows=sum(len(v) for v in kept.values()), provenance=provenance)
        if not args.verify_only:
            analysis = delivery / "analysis"
            jobs = [("summarize_workload.py", [])]
            if not args.skip_plots:
                jobs.append(("plot_results.py", ["--note", args.note]))
            for script, extra in jobs:
                with (delivery / (Path(script).stem + ".log")).open("w", encoding="utf-8") as log:
                    subprocess.run([sys.executable, "-X", "utf8", str(HERE / script),
                                    str(run), "--output", str(analysis), *extra],
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
            receipt["analysis_directory"] = str(analysis / run.name)
        receipt["status"] = "completed"
        print(f"Verified import: {delivery}")
        print(f"Run: {manifest['run_id']}; cases: {receipt['case_statuses']}")
        return 0
    except Exception as error:
        receipt.update(status="failed", error=f"{type(error).__name__}: {error}")
        print(f"Import/analysis stopped: {error}\nDiagnostic directory: {delivery}", file=sys.stderr)
        return 1
    finally:
        (delivery / "import_receipt.json").write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
