"""Exact v0.6.2 serialization accounting, checked against existing byte outputs.

This reads completed measurements; it does not execute a cryptographic benchmark,
estimate timings, or provide a security proof. Costs are BYTES, not group counts.
Only the fixed full-cohort main history is covered. Stress branches, transport
cache packets, heap usage and the separate RIPE comparator are explicitly excluded.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path


def core(tag, *fields):
    return 8 * (1 + len(fields)) + len(tag.encode()) + sum(fields)


def auth(tag, *fields):
    return len(b"CHARE-AUTH-FRAME\x00\x01") + 16 + len(tag.encode()) + 8 * len(fields) + sum(fields)


def lengths(n, m, source_bytes, target_bytes, scalar_bytes, parameters_bytes, updates=0, literals=1):
    """One full cohort; fixed-width fields; no reference/digest deduplication."""
    G, GT, L = source_bytes, target_bytes, scalar_bytes
    points = lambda count: core("points", 8, *([G] * count))
    protocol = len(b"CHARE-RATIONAL-BASE-PBC-v1")
    pp = core("CHARE-RATIONAL-CORE-v1/params", parameters_bytes, 8, L, G, G,
              points(n), points(n), points(n), points(n - 1), points(n - 1), G, GT)
    root = core("root", 32, 8, G, G, points(n - 1))
    root_message = auth("CHARE/authorized-root/v1", protocol, pp, 8, root)
    certified_root = auth("CHARE/certified-root/v1", root_message, 64, 32)
    row = core("decision-row", 32, 8, root, G, points(n - 1))
    metadata = auth("CHARE/issuance-context/v1", protocol, pp, 8, 8, 8, 8, 8, certified_root, row)
    precontext = auth("CHARE/scalar-delivery/context/v1", L, G, G, metadata, G, 8)
    delivery = auth("CHARE/scalar-delivery/wire/v1", G, precontext, L, 64)
    issued = auth("CHARE/issued/v1", metadata, row, delivery)
    history0 = core("fixed-cohort-dictionary", pp, 8, 8, *([root] * n), *([row] * (n * m)))
    update = core("row-update", 8, 8, 8, row)
    history = history0 + updates * update
    verifier = core("prepared-public-verifier", 32, 32, 8, 8, 8, points(m + 1), G, points(n), *([8] * n))
    sender = core("CHARE/public-sender-state/v1", 32, 32, 8, 8, 8, history, points(m + 1), G, *([8] * n))
    polynomial = core("polynomial", *([L] * n))
    prepared = core("prepared-public-state", 32, 8, 8, 8, history, points(m + 1), G, points(n), points(n),
                    *([points(n)] * (m + 1)), *([polynomial] * n))
    snapshot = auth("CHARE/full-current-snapshot/v2", protocol, pp, 8, 8, 8, verifier, sender,
                    *([certified_root] * n), *([32] * m), *([issued] * (n * m)))
    help_bytes = core("help", 32, 8, 8, G, G, points(m + 1), G)
    target_context = core("CHARE-RATIONAL-CORE-v1/target", history, snapshot, 32, 8, 8,
                          *([8, 1, L] * literals))
    ciphertext = core("ciphertext", 32, 8, target_context, G, G)
    return dict(parameters=pp, raw_root=root, certified_root=certified_root, raw_row=row,
                metadata=metadata, delivery=delivery, issued_record=issued,
                history_context=history, one_update=update, prepared_state=prepared,
                verifier=verifier, sender=sender, snapshot=snapshot, signed_snapshot=snapshot + 64,
                help=help_bytes, first_acquisition=auth("CHARE/acquisition/v1", snapshot, 64, help_bytes),
                refresh=auth("CHARE/refresh/v1", snapshot, 64, help_bytes),
                sender_acquisition=auth("CHARE/sender-acquisition/v1", snapshot, 64),
                target_context=target_context, ciphertext=ciphertext, cipher_core=2 * G)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run", type=Path, help="Existing completed v0.6.2 result directory")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    run = args.run.resolve()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("implementation_version") != "chare-go-pbc-v0.6.2":
        raise ValueError("Codec formulas are pinned to v0.6.2; review a new version before using them")
    par = manifest["parameters"]
    if digest(run / "parameters.txt") != par["sha256"]:
        raise ValueError("Parameter-file hash mismatch")
    widths = [par["g_bytes_uncompressed"], par["gt_bytes"], (par["r_bits_actual"] + 7) // 8,
              len((run / "parameters.txt").read_bytes())]
    with (run / "raw.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    checks, cases = [], []
    for case_id in dict.fromkeys(r["case_id"] for r in rows):
        case_rows = [r for r in rows if r["case_id"] == case_id and r["scheme"].startswith("CHARE")]
        first = case_rows[0]
        n, m, revocations = int(first["capacity"]), int(first["attributes"]), int(first["revocations"])
        initial = lengths(n, m, *widths)
        final = lengths(n, m, *widths, updates=revocations)
        epoch = 0
        for r in case_rows:
            op, mode = r["operation"], r["mode"]
            value, item = None, None
            fixed = {
                ("setup", "cold"): "parameters", ("user_keygen", "cold"): "raw_root",
                ("root_certify", "cold"): "certified_root", ("certify_and_deliver", "cold"): "issued_record",
                ("aggregate", "cold_after_full_validation"): "prepared_state",
                ("first_acquisition", "cold_full_manifest"): "first_acquisition",
                ("offline_denial_issue", "update"): "issued_record", ("moment_row_update", "warm"): "issued_record",
            }
            if (op, mode) in fixed:
                item = fixed[(op, mode)]
                value = initial[item]
            elif op == "snapshot_publish" and mode in ("cold", "update"):
                if mode == "update":
                    epoch += 1
                item = "signed_snapshot"
                value = lengths(n, m, *widths, updates=epoch)[item]
            elif (op, mode) == ("refresh", "warm_full_manifest"):
                item = "refresh"
                value = lengths(n, m, *widths, updates=epoch)[item]
            else:
                policy_mode = mode.removeprefix("after_updates_")
                if policy_mode in ("A", "not_A", "B", "A_and_B", "all_attributes"):
                    k = m if policy_mode == "all_attributes" else 2 if policy_mode == "A_and_B" else 1
                    t = revocations if mode.startswith("after_updates_") else 0
                    table = lengths(n, m, *widths, updates=t, literals=k)
                    item = {"prepare_policy": "target_context", "encapsulate": "ciphertext",
                            "cipher_core_bytes": "cipher_core", "help_generate": "help",
                            "sender_snapshot_acquisition": "sender_acquisition"}.get(op)
                    if item:
                        value = table[item]
            if value is not None:
                checks.append(dict(case=case_id, operation=op, mode=mode, epoch=epoch, item=item,
                                   expected_bytes=value, actual_bytes=int(r["bytes"]), match=value == int(r["bytes"])))
        if epoch != revocations:
            raise ValueError("Main-history update count does not match workload")
        acquisition_epochs = []
        epoch = 0
        for r in case_rows:
            if (r["operation"], r["mode"]) == ("snapshot_publish", "update"):
                epoch += 1
            if (r["operation"], r["mode"]) == ("refresh", "warm_full_manifest"):
                acquisition_epochs.append(epoch)
        cases.append(dict(case=case_id, capacity=n, attributes=m, updates=revocations,
                          initial=initial, final=final,
                          initial_all_user_acquisition_bytes=n * initial["first_acquisition"],
                          main_snapshot_publication_bytes=sum(lengths(n, m, *widths, updates=t)["signed_snapshot"]
                                                              for t in range(revocations + 1)),
                          main_adaptive_acquisition_epochs=acquisition_epochs,
                          main_adaptive_acquisition_bytes=sum(lengths(n, m, *widths, updates=t)["refresh"]
                                                             for t in acquisition_epochs),
                          distinct_initial_and_main_row_bodies_bytes=(n * m + revocations) * initial["issued_record"]))
    failed = [x for x in checks if not x["match"]]
    report = dict(schema="chare-v062-codec-accounting-v1", scope="existing byte-output checks only; no new timings/security evidence",
                  excluded="stress branches, cache packets, heap, RIPE implementation, parameter-strength calibration",
                  input_hashes={name: digest(run / name) for name in ("manifest.json", "parameters.txt", "raw.csv")},
                  widths=dict(zip(("source_bytes", "target_bytes", "scalar_bytes", "parameter_text_bytes"), widths)),
                  checked_rows=len(checks), failed_rows=len(failed), cases=cases, checks=checks)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "codec_accounting.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (args.output / "codec_checks.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(checks[0]))
        writer.writeheader()
        writer.writerows(checks)
    if failed:
        raise SystemExit(json.dumps(failed[:8], indent=2))
    print(json.dumps({"checked_rows": len(checks), "failed_rows": 0, "cases": cases}, indent=2))


if __name__ == "__main__":
    main()
