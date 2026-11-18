"""Summarize measured lifecycle intervals; never synthesize timings or costs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from plot_results import load, validate_effective_workload
from cold_audit_accounting import cold_audit_operations
from transport_accounting import transport_ledgers, VERSION as TRANSPORT_VERSION

VERSION = "chare-lifecycle-accounting-v5"
NUMERIC = ("duration_ns", "bytes", "source_ops", "pairings", "count")
FIELDS = ("scheme", "operation", "mode", *NUMERIC, "detail")
SUPPORTED = {"chare-go-pbc-v0.4.0", "chare-go-pbc-v0.4.1", "chare-go-pbc-v0.5.0", "chare-go-pbc-v0.5.1", "chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def fingerprint(row):
    result = []
    for key in FIELDS:
        value = int(row[key]) if key in NUMERIC else row[key]
        if key in NUMERIC and value < 0:
            raise ValueError(f"Negative measurement: {key}")
        result.append(value)
    return tuple(result)


def rules(n, m, r, a):
    """Required Count totals of distinct, non-nested measurement intervals."""
    c, ca, d = "CHARE", "CHARE-auth", "DH-explicit-list"
    result = {}
    def add(scheme, operation, mode, count, phase, component):
        result[(scheme, operation, mode)] = (count, phase, component)
    for s, op, mode, count, component in [
        (c,"setup","cold",1,"core"),
        (ca,"authority_keygen","cold",m+1,"authentication"),
        (c,"user_keygen","cold",n,"core"),
        (ca,"root_certify","cold",n,"authentication"),
        (c,"root_validate","cold",n,"mixed_validation"),
        (c,"certify_and_deliver","cold",n*m,"mixed_issuance"),
        (c,"record_validate","cold",n*m,"mixed_validation"),
        (c,"aggregate","cold_after_full_validation",1,"core"),
        (ca,"snapshot_publish","cold",1,"publication"),
        (c,"first_acquisition","cold_full_manifest",n,"client_acquisition"),
        (d,"setup_and_authority_keygen","cold",1,"mixed_setup"),
        (d,"user_keygen","cold",n,"core"),
        (d,"root_certify","cold",n,"authentication"),
        (d,"root_validate","cold",n,"authentication"),
        (d,"registry_publish","cold",1,"publication"),
        (d,"sender_registry_acquisition","cold_one_sender",1,"sender_acquisition"),
        (d,"authorization_publish","cold",1,"publication"),
        (d,"first_acquisition","cold_own_certificate_and_epoch",n,"client_acquisition"),
    ]:
        add(s,op,mode,count,"initialization",component)
    for s, op, mode, count, component in [
        (c,"offline_denial_issue","update",r,"mixed_issuance"),
        (c,"offline_denial_validate","update",r,"mixed_validation"),
        (c,"moment_row_update","warm",r,"core"),
        (ca,"snapshot_publish","update",r,"publication"),
        (c,"refresh","warm_full_manifest",a,"client_acquisition"),
        (d,"authorization_publish","update",r,"publication"),
        (d,"refresh","warm_current_epoch",a,"client_acquisition"),
    ]:
        add(s,op,mode,count,"updates_and_acquisitions",component)
    return result


def summarize_case(case, config, rows):
    rule = rules(config["capacity"], config["attributes"], config["revocations"], config["acquisitions"])
    grouped = defaultdict(list)
    for row in rows:
        fingerprint(row)
        grouped[tuple(row[k] for k in ("scheme","operation","mode"))].append(row)
    operations, excluded = [], []
    dims = {"case_id":case, **config}
    for key, (expected, phase, component) in rule.items():
        rr = grouped.pop(key, [])
        actual = sum(int(row["count"]) for row in rr)
        if actual != expected or (expected == 0 and rr):
            raise ValueError(f"{case}: missing/duplicated lifecycle operation {key}: {actual} != {expected}")
        if any("no timing sample" in row["detail"] or int(row["count"]) <= 0 for row in rr):
            raise ValueError(f"{case}: lifecycle interval is not a timed execution: {key}")
        scheme, op, mode = key
        operations.append({**dims, "scheme":"CHARE" if scheme=="CHARE-auth" else scheme,
                           "raw_scheme":scheme, "phase":phase, "component":component,
                           "operation":op, "mode":mode, "measurement_rows":len(rr),
                           "zero_duration_rows":sum(int(row["duration_ns"])==0 for row in rr),
                           **{k:sum(int(row[k]) for row in rr) for k in NUMERIC}})
    for key, rr in sorted(grouped.items()):
        s,op,mode=key
        reason = ("optional_transport" if op.startswith("transport_") else
                  "synthetic_selector_not_hidden_service" if op=="authorized_list_test_oracle" else
                  "stress_or_snapshot_observation" if mode.startswith("stress_") or op=="retained_history_storage" else
                  "separate_policy_or_diagnostic_execution")
        excluded.append({**dims,"scheme":s,"operation":op,"mode":mode,"reason":reason,
                         "measurement_rows":len(rr), **{k:sum(int(row[k]) for row in rr) for k in NUMERIC}})
    totals=[]
    for scheme in ("CHARE","DH-explicit-list"):
        for phase in ("initialization","updates_and_acquisitions"):
            rr=[row for row in operations if row["scheme"]==scheme and row["phase"]==phase]
            totals.append({**dims,"scheme":scheme,"phase":phase,
                "measured_interval_ns":sum(row["duration_ns"] for row in rr),
                "zero_duration_rows":sum(row["zero_duration_rows"] for row in rr),
                "source_ops":sum(row["source_ops"] for row in rr),
                "pairings":sum(row["pairings"] for row in rr),
                "client_acquisition_bytes":sum(row["bytes"] for row in rr if row["component"]=="client_acquisition"),
                "sender_acquisition_bytes":sum(row["bytes"] for row in rr if row["component"]=="sender_acquisition"),
                "measurement_rows":sum(row["measurement_rows"] for row in rr)})
    return operations, totals, excluded


def audit_input(run):
    # Guard paths and require checksums for every used file BEFORE legacy loader
    # opens case paths. Checksums establish integrity, not experimental honesty.
    raw = read_csv(run/"raw.csv")
    listed = set()
    for line in (run/"SHA256SUMS").read_text(encoding="utf-8-sig").splitlines():
        digest, relative = line.split("  ",1)
        if relative in listed or not re.fullmatch(r"[0-9a-fA-F]{64}",digest):
            raise ValueError("Invalid/duplicate checksum entry")
        path=(run/relative).resolve()
        if not path.is_relative_to(run.resolve()):
            raise ValueError("Checksum path outside run")
        listed.add(relative)
    required={"raw.csv","manifest.json","status.json","config.json","parameters.txt","source_manifest.json","checks.csv"}
    for row in raw:
        if not re.fullmatch(r"case_[0-9]+_n[0-9]+_m[0-9]+_r[0-9]+",row["case_id"]):
            raise ValueError("Invalid case identity")
    states = {}
    for directory in sorted((run/"cases").iterdir()):
        if not directory.is_dir() or not re.fullmatch(r"case_[0-9]+_n[0-9]+_m[0-9]+_r[0-9]+",directory.name):
            raise ValueError("Unexpected case entry")
        state=read_json(directory/"status.json")
        if state["case_id"]!=directory.name:
            raise ValueError("Case directory/status identity mismatch")
        states[directory.name]=state
        required.add(f"cases/{directory.name}/status.json")
        if state["status"]=="passed":
            required.update({f"cases/{directory.name}/result.json",f"cases/{directory.name}/checks.json"})
    if not required.issubset(listed):
        raise ValueError("Checksum manifest does not cover required inputs: "+str(sorted(required-listed)))
    filtered, manifest, provenance=load(run)
    if any(row["run_id"]!=manifest["run_id"] for row in raw):
        raise ValueError("Raw rows contain another run identity")
    if manifest.get("implementation_version") not in SUPPORTED:
        raise ValueError("Accounting map is not audited for this implementation version")
    if len(states)!=manifest.get("planned_cases"):
        raise ValueError("Planned case status records are incomplete")
    run_status=read_json(run/"status.json")
    for key,name in [("passed","passed"),("failed","failed"),("skipped","skipped")]:
        if sum(s["status"]==name for s in states.values())!=run_status[key]:
            raise ValueError("Run status disagrees with case outcomes")
    kept=defaultdict(list)
    for row in filtered:
        kept[row["case_id"]].append(row)
    flat_checks=read_csv(run/"checks.csv")
    for case,state in states.items():
        if state["status"]!="passed":
            continue
        result=read_json(run/"cases"/case/"result.json")
        cfg=state["configuration"]
        validate_effective_workload(cfg,result.get("workload_evidence"))
        if manifest["implementation_version"] in {"chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
            declared=manifest["configuration"]["workload"].get("cold_audit_all_users",False)
            if cfg.get("cold_audit_all_users") != declared:
                raise ValueError("Cold-audit case scope differs from run configuration")
            cold_audit_operations(case,cfg,result.get("cold_audit_evidence"),kept[case],manifest["implementation_version"])
        if not kept[case] or Counter(map(fingerprint,kept[case]))!=Counter(map(fingerprint,result["measurements"])):
            raise ValueError("Raw rows differ from complete case measurements: "+case)
        for row in kept[case]:
            if any(int(row[k])!=cfg[k] for k in ("capacity","attributes","replicate","revocations","acquisitions")):
                raise ValueError("Raw dimensions disagree with case configuration")
        check_rows=[row for row in flat_checks if row["case_id"]==case]
        if not result["checks"] or any(c["passed"] is not True for c in result["checks"]) or len(result["checks"])!=state["checks"]:
            raise ValueError("Passed case has incomplete/failing checks")
        if result["checks"]!=read_json(run/"cases"/case/"checks.json") or Counter((c["name"],str(c["passed"]).lower(),c["detail"]) for c in result["checks"])!=Counter((c["name"],c["passed"],c["detail"]) for c in check_rows):
            raise ValueError("Case/CSV checks differ")
        transport_ledgers(case,cfg,kept[case],result["checks"],manifest["implementation_version"])
    return kept,states,manifest,provenance


def sender_operations(case, config, rows, version):
    """Separate sender acquisition ledger; these are also raw/excluded rows.

    Do not add this table to lifecycle_cases: the initial DH registry row
    already belongs to initialization. No row is invented for old CHARE runs.
    """
    policies = ["A", "not_A"]
    if config["attributes"] >= 2:
        policies += ["B", "A_and_B"]
    if config["attributes"] > 2:
        policies += ["all_attributes"]
    modes = policies + ["after_updates_" + p for p in policies]
    if version in {"chare-go-pbc-v0.5.1","chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
        modes += ["stress_changed_cohort_A", "stress_regrant_A"]
    allowed = {("CHARE", "sender_snapshot_acquisition"),
               ("DH-explicit-list", "sender_registry_acquisition"),
               ("DH-explicit-list", "sender_authorization_acquisition")}
    selected = [row for row in rows if (row["scheme"], row["operation"]) in allowed]
    for scheme, op in [("DH-explicit-list", "sender_authorization_acquisition")]+(
            [("CHARE", "sender_snapshot_acquisition")] if version in {"chare-go-pbc-v0.5.0", "chare-go-pbc-v0.5.1", "chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"} else []):
        for mode in modes:
            rr = [row for row in selected if (row["scheme"],row["operation"],row["mode"])==(scheme,op,mode)]
            if len(rr)!=1 or int(rr[0]["count"])!=1 or int(rr[0]["bytes"])<=0 or "no timing sample" in rr[0]["detail"]:
                raise ValueError(f"Missing/duplicated/unmeasured sender acquisition: {case} {scheme} {mode}")
    output=[]
    for row in selected:
        fingerprint(row)
        mode=row["mode"]
        phase=("initial_registry" if row["operation"]=="sender_registry_acquisition" else
               "stress" if mode.startswith("stress_") else
               "policy_after_updates" if mode.startswith("after_updates_") else "policy_initial")
        output.append({"case_id":case,**config,"scheme":row["scheme"],"phase":phase,
                       "operation":row["operation"],"mode":mode,**{k:int(row[k]) for k in NUMERIC},
                       "also_in_lifecycle":row["operation"]=="sender_registry_acquisition"})
    return output


def write_csv(path,rows):
    if not rows:
        return
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run",type=Path)
    ap.add_argument("--output",type=Path,default=Path(__file__).resolve().parent/"output")
    args=ap.parse_args()
    run=args.run.resolve()
    kept,states,manifest,provenance=audit_input(run)
    operations,totals,excluded,senders,cold=[],[],[],[],[]
    packets,transport_phases,transport_coverage=[],[],[]
    for case,rr in sorted(kept.items()):
        oo,tt,ee=summarize_case(case,states[case]["configuration"],rr)
        operations.extend(oo); totals.extend(tt); excluded.extend(ee)
        senders.extend(sender_operations(case,states[case]["configuration"],rr,manifest["implementation_version"]))
        result=read_json(run/"cases"/case/"result.json")
        cold.extend(cold_audit_operations(case,states[case]["configuration"],result.get("cold_audit_evidence"),rr,manifest["implementation_version"]))
        pp,tp,tc=transport_ledgers(case,states[case]["configuration"],rr,result["checks"],manifest["implementation_version"])
        packets.extend(pp);transport_phases.extend(tp);transport_coverage.extend(tc)
    if not totals:
        raise ValueError("No passed measured case")
    groups=defaultdict(list)
    dims=("scheme","phase","capacity","attributes","revocations","acquisitions")
    metrics=("measured_interval_ns","zero_duration_rows","source_ops","pairings","client_acquisition_bytes","sender_acquisition_bytes")
    for row in totals:
        groups[tuple(row[k] for k in dims)].append(row)
    replicated=[]
    for key,rr in sorted(groups.items()):
        out=dict(zip(dims,key)); out["replicates"]=len(rr)
        for metric in metrics:
            values=[row[metric] for row in rr]
            out[metric+"_median"]=statistics.median(values)
            out[metric+"_min"]=min(values); out[metric+"_max"]=max(values)
        replicated.append(out)
    output=args.output/run.name
    output.mkdir(parents=True,exist_ok=True)
    write_csv(output/"lifecycle_operations.csv",operations)
    write_csv(output/"lifecycle_cases.csv",totals)
    write_csv(output/"lifecycle_replicates.csv",replicated)
    write_csv(output/"lifecycle_exclusions.csv",excluded)
    write_csv(output/"sender_acquisitions.csv",senders)
    write_csv(output/"cold_audits.csv",cold)
    write_csv(output/"transport_packets.csv",packets)
    write_csv(output/"transport_phases.csv",transport_phases)
    write_csv(output/"transport_coverage.csv",transport_coverage)
    scope={"accounting_version":VERSION,"run":str(run),"implementation_version":manifest["implementation_version"],
        "parameters":manifest["parameters"],"provenance":provenance,
        "script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "cold_audit_dependency_sha256":hashlib.sha256(Path(__file__).with_name("cold_audit_accounting.py").read_bytes()).hexdigest(),
        "transport_accounting_version":TRANSPORT_VERSION,
        "transport_dependency_sha256":hashlib.sha256(Path(__file__).with_name("transport_accounting.py").read_bytes()).hexdigest(),
        "transport_scope":"v0.6.0/v0.6.1 original traces only: actual publications, N separate installations, packet outputs and local full-byte expansion are separate columns. Serialization is not network transmission. Empty DH lists and uninstrumented stress profiles are explicit coverage states, not zero-cost samples. Fresh-repeat cryptography is separate from adapter intervals. These rows already occur in exclusions; do not add the views twice. Older implementations receive no new transport certification.",
        "failed_or_skipped":{k:v["status"] for k,v in states.items() if v["status"]!="passed"},
        "time_scope":"Sum of named measured non-nested intervals per case, NOT network wall-clock latency or full process CPU time; no multiplication by count.",
        "zero_duration_scope":"Recorded zero-nanosecond intervals are retained and counted, NOT interpreted as zero-cost operations or used for an infinite speedup. Timer precision/quantization is not certified.",
        "bytes_scope":"Only actual named acquisition payloads aggregated by receiver role; publication/materialization outputs retained per operation, NOT summed as end-to-end network traffic.",
        "excluded":"Optional transport, policy exercises, stress branches, storage snapshots and synthetic list oracle are retained separately; no missing implementation is assigned zero cost.",
        "comparison_scope":"DH requires an externally supplied public authorized set. Its hidden-selector cost is unimplemented. No same-functionality or equal-security speedup is claimed.",
        "missing_complete_deployment_costs":(["CHARE sender's snapshot acquisition/validation interface"] if manifest["implementation_version"] not in {"chare-go-pbc-v0.5.0","chare-go-pbc-v0.5.1","chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"} else [])+(["authenticated typed-sender acquisition in changed-cohort/regrant stress diagnostics"] if manifest["implementation_version"] not in {"chare-go-pbc-v0.5.1","chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"} else [])+["hostile network input decoding","network framing, bandwidth, latency and retransmissions","full process memory including native objects","external hidden authorized-list production for DH"],
        "sender_scope":"sender_acquisitions.csv is a separate view of raw rows, not an extra additive cost. Initial DH registry acquisition already belongs to lifecycle initialization. v0.5.0 adds main-policy CHARE acquisition; v0.5.1 also requires both schemes' changed-cohort/regrant acquisitions. Stress rows remain outside main lifecycle totals. No sender caching or minimum-cost claim; old missing rows are not zero-cost operations.",
        "cold_audit_scope":"cold_audits.csv reconciles individual measured clients; v0.6.0 independently replays the complete public history. Earlier rows cover one client current-record checks only. All cold-audit rows also appear in exclusions and must not be added twice. No multiplication of one sample by client count.",
        "version_scope":"v0.6.1 adds pre-native parameter admission without changing the measured workload protocol; v0.6.0 adds independent all-client cold audits and explicit scope; v0.4.0 lacks v0.4.1 authentication corrections; v0.5.0 adds sender state and snapshot v2; v0.5.1 adds authenticated branch snapshots and stress measurements. Runs are never pooled.",
        "replicate_scope":"Observed min/max, not confidence intervals. All measurements remain linked to original case identities."}
    (output/"lifecycle_scope.json").write_text(json.dumps(scope,indent=2,ensure_ascii=False)+'\n',encoding="utf-8")
    print(output)


if __name__=="__main__":
    main()
