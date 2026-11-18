"""Reconcile actual independent client audits; no extrapolated observations."""
import re

PROFILE = "typed-public-history-replay-v1"


def cold_audit_operations(case, config, evidence, rows, version):
    selected = [r for r in rows if r["operation"] == "cold_audit"]
    if version not in {"chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}:
        return [{"case_id":case, **config, "scope":"legacy_one_client_record_checks_no_replay_claim",
                 **{k:r[k] for k in ("scheme","operation","mode","detail")},
                 **{k:int(r[k]) for k in ("duration_ns","bytes","source_ops","pairings","count")}}
                for r in selected]
    flag = config.get("cold_audit_all_users")
    if not isinstance(flag, bool):
        raise ValueError("Missing/ambiguous cold-audit configuration")
    count = config["capacity"] if flag else 1
    mode = "stress_all_clients_replay" if flag else "stress_one_client_replay"
    if not evidence or evidence.get("profile") != PROFILE or evidence.get("clients") != count:
        raise ValueError("Missing independent cold-audit evidence")
    entries = evidence.get("entries", [])
    expected = {(s,i) for s in ("CHARE","DH-explicit-list") for i in range(count)}
    keys = [(e.get("scheme"),e.get("slot")) for e in entries]
    if len(keys)!=len(expected) or set(keys)!=expected:
        raise ValueError("Duplicate/missing cold-audit client")
    if len(selected)!=len(expected):
        raise ValueError("Cold-audit rows do not cover actual clients")
    actual = {}
    for r in selected:
        slots=re.findall(r"(?:^|;)cold_client_slot=([0-9]+)(?:;|$)",r["detail"])
        seqs=re.findall(r"(?:^|;)cold_sequence=([0-9]+)(?:;|$)",r["detail"])
        if len(slots)!=1 or len(seqs)!=1 or int(seqs[0])!=config["revocations"]:
            raise ValueError("Unidentified cold-audit interval")
        key=(r["scheme"],int(slots[0]))
        if key not in expected or key in actual or r["mode"]!=mode or int(r["count"])!=1 or "no timing sample" in r["detail"]:
            raise ValueError("Duplicated/unmeasured cold-audit interval")
        for k in ("duration_ns","bytes","source_ops","pairings"):
            if int(r[k])<0: raise ValueError("Negative cold-audit observation")
        if r["scheme"]=="CHARE":
            n,m,t=config["capacity"],config["attributes"],config["revocations"]
            expected_pairings=2*((m+1)*n+t)*(n-1)+2*(m+3)
            if int(r["pairings"])!=expected_pairings:
                raise ValueError("Cold-audit full-array/helper pairing count mismatch")
        actual[key]=r
    output=[]
    for e in entries:
        r=actual[(e["scheme"],e["slot"])]
        if e.get("sequence")!=config["revocations"] or e.get("bytes",0)<=0 or e["bytes"]!=int(r["bytes"]):
            raise ValueError("Cold-audit endpoint/payload differs from actual measurement")
        output.append({"case_id":case,**config,"scope":PROFILE,"client_slot":e["slot"],
                       "sequence":e["sequence"], **{k:r[k] for k in ("scheme","operation","mode","detail")},
                       **{k:int(r[k]) for k in ("duration_ns","bytes","source_ops","pairings","count")}})
    return output
