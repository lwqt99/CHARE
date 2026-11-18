"""Plot measured CHARE Go/PBC outputs only. Never generates benchmark samples."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import textwrap
from collections import defaultdict
from pathlib import Path


def validate_effective_workload(config, evidence):
    """Validate synthetic event provenance; this is not a security experiment."""
    if not isinstance(evidence, dict):
        raise ValueError("Missing effective-revocation evidence.")
    n, m = config["capacity"], config["attributes"]
    requested, acquisitions = config["revocations"], config["acquisitions"]
    initial = sum((slot >> (a % 63)) & 1 for slot in range(n) for a in range(m))
    expected = {
        "schedule": "synthetic-active-only-slot-major-v1",
        "initial_active_qualifications": initial,
        "requested_revocations": requested,
        "completed_effective_revocations": requested,
        "requested_acquisitions": acquisitions,
        "completed_acquisitions": acquisitions,
    }
    if any(evidence.get(k) != value for k, value in expected.items()):
        raise ValueError("Workload completion or fixture counts do not match the case.")
    events = evidence.get("events")
    if not isinstance(events, list) or len(events) != requested or requested > initial:
        raise ValueError("Missing revocation events or an impossible active-only workload.")
    selections = ((slot, a) for slot in range(n) for a in range(m) if (slot >> (a % 63)) & 1)
    for step, event in enumerate(events, 1):
        slot, a = next(selections)
        if not isinstance(event, dict) or any(event.get(k) != value for k, value in {
            "step": step, "slot": slot, "attribute": a,
            "previous_version": 1, "installed_version": 2, "sequence": step,
        }.items()) or event.get("before") is not True or event.get("after") is not False or \
                event.get("chare_installed") is not True or event.get("baseline_published") is not True:
            raise ValueError(f"Event {step} is not the expected completed distinct 1-to-0 transition.")
    return {"effective_revocations": requested, "paired_acquisitions": acquisitions, "schedule": expected["schedule"]}


def audit_refresh_profile(manifest):
    """Record executed interface scope; metadata is not a security certificate."""
    expected = "signed-state-binding-and-atomic-local-open-v1"
    if manifest.get("implementation_version") in {"chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
        if manifest.get("receiver_refresh_profile") != expected:
            raise ValueError("Missing or incompatible receiver refresh profile for v0.6.2.")
        return {"profile": expected, "scope": "Actual snapshot reserialization/binding and staged local openings are charged; freshness remains external."}
    return {"profile": "legacy_not_upgraded", "scope": "Earlier runs do not include the v0.6.2 receiver binding/transaction correction."}


def load(run: Path):
    raw = run / "raw.csv"
    if not raw.is_file():
        raise ValueError("Pass an extracted run directory containing raw.csv.")
    manifest_path = run / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Missing manifest.json; use the complete returned run directory.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    refresh_profile = audit_refresh_profile(manifest)
    from parameter_accounting import audit_parameters
    parameter_admission = audit_parameters(run, manifest)
    sums_path = run / "SHA256SUMS"
    if not sums_path.is_file():
        raise ValueError("Missing SHA256SUMS; the batch may not have finalized.")
    for line in sums_path.read_text(encoding="utf-8-sig").splitlines():
        digest, relative = line.split("  ", 1)
        target = (run / relative).resolve()
        if not target.is_relative_to(run.resolve()):
            raise ValueError("Hash manifest contains an out-of-directory path.")
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest().lower() != digest.lower():
            raise ValueError(f"Integrity check failed: {relative}")
    with raw.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    required = {"case_id", "capacity", "attributes", "replicate", "scheme", "operation", "mode", "duration_ns", "bytes", "count"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("No measurements, or incompatible raw.csv schema.")
    accepted = {}
    workload_audit = {}
    for row in rows:
        case = row["case_id"]
        if case not in accepted:
            status_path = run / "cases" / case / "status.json"
            if not status_path.is_file():
                raise ValueError(f"Missing completion status for {case}; refusing partial results.")
            status = json.loads(status_path.read_text(encoding="utf-8-sig"))
            accepted[case] = status.get("status") == "passed"
            if accepted[case] and manifest.get("implementation_version") in {"chare-go-pbc-v0.4.0", "chare-go-pbc-v0.4.1", "chare-go-pbc-v0.5.0", "chare-go-pbc-v0.5.1", "chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
                if manifest.get("workload_schedule") != "synthetic-active-only-slot-major-v1":
                    raise ValueError("Unexpected workload schedule in effective-withdrawal manifest.")
                case_result = json.loads((status_path.parent / "result.json").read_text(encoding="utf-8-sig"))
                workload_audit[case] = validate_effective_workload(status["configuration"], case_result.get("workload_evidence"))
    filtered = [r for r in rows if accepted[r["case_id"]]]
    if not filtered:
        raise ValueError("No passed cases to plot. Inspect failure records first.")
    return filtered, manifest, {"raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(), "parameter_admission": parameter_admission, "receiver_refresh": refresh_profile, "rejected_cases": sorted(k for k, v in accepted.items() if not v), "effective_workload_audit": workload_audit, "workload_scope": "validated effective withdrawals" if workload_audit else "legacy or unspecified schedule: update counts do not establish effective withdrawals"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run", type=Path)
    ap.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "output")
    ap.add_argument("--note", default="", help="Visible scope label, e.g. local pipeline validation only.")
    args = ap.parse_args()
    rows, manifest, provenance = load(args.run)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "Times New Roman", "mathtext.fontset": "stix", "pdf.fonttype": 42})

    out = args.output / args.run.resolve().name
    out.mkdir(parents=True, exist_ok=True)
    # Aggregate repeated operations within each replicate before combining replicates.
    groups = defaultdict(list)
    for row in rows:
        key = (row["scheme"], row["operation"], row["mode"], int(row["attributes"]), int(row["capacity"]), row["case_id"])
        groups[key].append(row)
    observations = defaultdict(list)
    for key, rr in groups.items():
        count = sum(int(r["count"]) for r in rr)
        if count <= 0:
            continue
        timed = [r for r in rr if "no timing sample" not in r.get("detail", "")]
        timed_count = sum(int(r["count"]) for r in timed)
        elapsed = sum(int(r["duration_ns"]) for r in timed) / timed_count / 1e6 if timed_count else None
        observations[key[:-1]].append((elapsed, sum(int(r["bytes"]) for r in rr) / count))
    table = []
    for key, vals in sorted(observations.items()):
        times = [x[0] for x in vals if x[0] is not None]
        sizes = [x[1] for x in vals]
        table.append(dict(zip(("scheme", "operation", "mode", "attributes", "capacity"), key), replicates=len(vals), timed_replicates=len(times), median_ms=statistics.median(times) if times else None, min_ms=min(times) if times else None, max_ms=max(times) if times else None, median_bytes=statistics.median(sizes)))
    with (out / "measured_table.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(table[0]))
        writer.writeheader()
        writer.writerows(table)
    # Separate operation/mode AND units. Bytes are the recorded operation
    # output, which can be local storage/expansion rather than network traffic.
    panels = defaultdict(list)
    for row in table:
        key = (row["operation"], row["mode"], row["attributes"])
        if row["timed_replicates"]:
            panels[("time", *key)].append(row)
        if row["median_bytes"] > 0:
            panels[("bytes", *key)].append(row)
    outputs = []
    for index, ((metric, operation, mode, m), data) in enumerate(sorted(panels.items())):
        fig, ax = plt.subplots(figsize=(5.2, 3.7), layout="constrained")
        for series, scheme in enumerate(sorted({r["scheme"] for r in data})):
            rr = sorted((r for r in data if r["scheme"] == scheme), key=lambda r: r["capacity"])
            style = {"marker": ("o", "s", "^", "D")[series % 4], "linestyle": ("-", "--", "-.", ":")[series % 4]}
            if metric == "time":
                y = [r["median_ms"] for r in rr]
                ax.errorbar([r["capacity"] for r in rr], y, yerr=[[r["median_ms"]-r["min_ms"] for r in rr], [r["max_ms"]-r["median_ms"] for r in rr]], capsize=3, label=scheme, **style)
            else:
                ax.plot([r["capacity"] for r in rr], [r["median_bytes"] for r in rr], label=scheme, **style)
        ylabel = "Measured time per operation (ms)" if metric == "time" else "Serialized bytes per reported operation"
        title = "\n".join(textwrap.wrap(operation, width=48)) + "\n" + "\n".join(textwrap.wrap(f"{mode} / m={m}", width=48))
        ax.set(xlabel="Capacity N", ylabel=ylabel)
        ax.set_title(title, fontsize=9)
        ax.set_ylim(bottom=0)
        if args.note:
            fig.supxlabel("\n".join(textwrap.wrap(args.note, width=74)), fontsize=8)
        ax.grid(alpha=.25)
        ax.legend(fontsize=8)
        stem = f"{index:03d}_{metric}_{''.join(c if c.isalnum() else '_' for c in operation+'_'+mode)}"
        for extension in ("pdf", "png"):
            path = out / f"{stem}.{extension}"
            fig.savefig(path, dpi=300)
            outputs.append(path.name)
        plt.close(fig)
    (out / "provenance.json").write_text(json.dumps({"input": str(args.run.resolve()), "manifest": manifest, **provenance, "display_note": args.note, "figure_width_inches": 5.2, "plot_role": "standalone diagnostic; manuscript sizing and caption require a separate selection", "aggregation": "Per-case sum(duration)/sum(count), then replicate median; time bars show observed min/max, not a confidence interval.", "bytes_scope": "Actual serialized operation outputs; cache publication/installation, packet transfer and local expansion are separate. Do not sum them as network traffic or omit cold setup.", "comparison_scope": "Data-plane baseline requires an explicit authorized list; no hidden-qualification equivalence or security-bit equivalence is inferred.", "outputs": outputs}, indent=2), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
