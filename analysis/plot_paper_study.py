"""Validate and plot only complete native Go study returns; no timing estimates."""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path

from summarize_workload import audit_input, read_json, summarize_case
from transport_accounting import transport_ledgers

VERSION = "chare-native-study-analysis-v1"


def validate_study(cfg, evidence):
    n = cfg["capacity"]
    if not cfg.get("paper_study") or not evidence or evidence.get("schema") != "chare-native-study-v1":
        raise ValueError("Missing native study, not eligible for the new evaluation")
    for name in ("helper_equal", "own_helper_equal", "old_state_unchanged", "changed_cohort_rejected"):
        if evidence.get(name) is not True:
            raise ValueError("Unsuccessful paired check: " + name)
    expected_order = ["rebuild", "delta"] if cfg["replicate"] % 2 else ["delta", "rebuild"]
    if evidence.get("comparison_order") != expected_order:
        raise ValueError("Unexpected paired execution order")
    services = evidence.get("services", [])
    if len(services) != 2:
        raise ValueError("Missing service alternative")
    for index, graph in enumerate(("tree", "cycle")):
        s = services[index]
        expected = dict(graph=graph, participants=n, directions=2, edges=n-1+index,
                        contributions=2*n, pad_deliveries=2*(n-1+index), aggregate_equal=True,
                        strict_prefix_protected=True, one_pad_protected=graph == "cycle",
                        cut_pads_protected=False, recovery_key_equal=True)
        if any(s.get(k) != v for k, v in expected.items()):
            raise ValueError("Service transcript outcome differs from the specified case")


def collect(run, validation_only=False):
    kept, states, manifest, provenance = audit_input(run)
    c = manifest["configuration"]
    if manifest.get("implementation_version") != "chare-go-pbc-v0.7.0":
        raise ValueError("New study requires v0.7.0; do not pool historical runs")
    if manifest.get("status") != "completed" or len(states) != 9 or any(s["status"] != "passed" for s in states.values()):
        raise ValueError("All nine planned cases must finish; no partial-case figures")
    if c["capacities"] != [4, 8, 16] or c["attributes"] != [2] or c["replicates"] != 3 or not c.get("paper_study"):
        raise ValueError("Different grid requires a separate analysis contract")
    if not validation_only and (c["curve"]["r_bits"], c["curve"]["q_bits"]) != (256, 1536):
        raise ValueError("Functional-test parameters are not paper measurement parameters")
    records, accounting, checks = [], [], []

    def add(case, cfg, metric, series, unit, value):
        if value < 0:
            raise ValueError("Negative observation")
        records.append(dict(case_id=case, capacity=cfg["capacity"], replicate=cfg["replicate"],
                            metric=metric, series=series, unit=unit, value=value))

    for case, state in states.items():
        cfg, rows = state["configuration"], kept[case]
        result = read_json(run / "cases" / case / "result.json")
        validate_study(cfg, result.get("study_evidence"))
        checks.append(dict(case_id=case, **result["study_evidence"]))
        ops, totals, excluded = summarize_case(case, cfg, rows)
        accounting.extend(ops + excluded)
        for t in totals:
            add(case, cfg, t["phase"], t["scheme"], "s", t["measured_interval_ns"]/1e9)

        def one(scheme, op, mode):
            found = [r for r in rows if (r["scheme"], r["operation"], r["mode"]) == (scheme, op, mode)]
            if len(found) != 1:
                raise ValueError(f"Missing/duplicate observation: {scheme}/{op}/{mode}")
            return found[0]

        for op in ("directory_update", "client_helper_update"):
            for scheme in ("CHARE-rebuild", "CHARE-delta"):
                r = one(scheme, op, "same_cohort")
                add(case, cfg, op, scheme.removeprefix("CHARE-"), "ms", int(r["duration_ns"])/1e6)
        packets, _, coverage = transport_ledgers(case, cfg, rows, result["checks"], manifest["implementation_version"])
        for policy in ("A", "after_updates_A", "stress_changed_cohort_A", "stress_regrant_A"):
            for kind in ("first", "fresh_repeat"):
                rr = [p for p in packets if p["scheme"] == "CHARE" and p["policy_mode"] == policy and p["kind"] == kind]
                if len(rr) != 1:
                    raise ValueError("Missing exact captured transport path")
                r = rr[0]
                # One actual serialized full object versus packet plus its new
                # entry if applicable. N-client installs are separately retained.
                add(case, cfg, "transport_"+policy+"_"+kind, "full", "MiB", r["full_ciphertext_bytes"]/2**20)
                add(case, cfg, "transport_"+policy+"_"+kind, "reference", "MiB",
                    (r["packet_output_bytes"]+r["publication_output_bytes"])/2**20)
                add(case, cfg, "entry_fanout_"+policy+"_"+kind, "reference", "MiB", r["client_installation_bytes"]/2**20)
        for graph in ("tree", "cycle"):
            scheme = "CHARE-service-"+graph
            operations = (("pad_sample_deliver_install", "all_directions"),
                          ("plan_readiness", "all_holders"),
                          ("contribute_and_authenticate", "all_directions"),
                          ("aggregate", "all_directions"))
            timed = [one(scheme, op, mode) for op, mode in operations]
            add(case, cfg, "service_execution", graph, "ms", sum(int(r["duration_ns"]) for r in timed)/1e6)
            # Aggregate output isn't a sent message; exclude it here.
            add(case, cfg, "service_serialized_messages", graph, "MiB", sum(int(r["bytes"]) for r in timed[:-1])/2**20)
            for mode in ("strict_prefix", "one_pad_exposure", "boundary_pad_exposure", "completed_no_exposure"):
                r = one(scheme, "coefficient_audit", mode)
                add(case, cfg, "audit_"+mode, graph, "ms", int(r["duration_ns"])/1e6)
            r = one(scheme, "recover_old_key", "explicit_mask_and_boundary_opening")
            add(case, cfg, "native_recovery", graph, "ms", int(r["duration_ns"])/1e6)
        # summarize_case's excluded rows already retain the complete study
        # intervals. Do not append those rows again or double-charge them.
    return records, accounting, checks, manifest, provenance


def summarize(records):
    groups = defaultdict(list)
    for r in records:
        groups[(r["metric"], r["series"], r["unit"], r["capacity"])].append(r)
    summary = []
    for key, rows in sorted(groups.items()):
        if sorted(r["replicate"] for r in rows) != [1, 2, 3]:
            raise ValueError("Expected three distinct case replicates per series")
        values = [r["value"] for r in rows]
        summary.append(dict(zip(("metric", "series", "unit", "capacity"), key),
                            median=statistics.median(values), minimum=min(values), maximum=max(values), samples=3))
    return summary


def write_csv(path, rows):
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)


def draw(summary, out, validation_only):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family":"Times New Roman", "mathtext.fontset":"stix", "font.size":9,
                         "pdf.fonttype":42, "ps.fonttype":42, "svg.fonttype":"none"})
    panels = [
        ("lifecycle", [("initialization", "Initialization (s)"), ("updates_and_acquisitions", "Withdrawals and acquisitions (s)")], True),
        ("helper", [("directory_update", "Directory update (ms)"), ("client_helper_update", "Receiver helper update (ms)")], False),
        ("transport", [("transport_A_first", "First A output + new entry (MiB)"), ("transport_A_fresh_repeat", "Repeat A output (MiB)")], True),
        ("service", [("service_execution", "Service execution (ms)"), ("service_serialized_messages", "Serialized service messages (MiB)")], False),
    ]
    labels = {"CHARE":"CHARE", "DH-explicit-list":"DH (public authorized list)", "rebuild":"Rebuild", "delta":"Delta / cached", "full":"Full context", "reference":"Exact reference", "tree":"Tree", "cycle":"Cycle"}
    for name, specs, logarithmic in panels:
        fig, axes = plt.subplots(1, 2, figsize=(7.04, 2.48))
        fig.subplots_adjust(left=.085, right=.985, bottom=.23, top=.95, wspace=.38)
        for panel, (ax, (metric, ylabel)) in enumerate(zip(axes, specs)):
            data = [r for r in summary if r["metric"] == metric]
            for index, series in enumerate(sorted({r["series"] for r in data})):
                rr = sorted((r for r in data if r["series"]==series), key=lambda r:r["capacity"])
                y=[r["median"] for r in rr]
                if logarithmic and min(y)<=0: raise ValueError("Nonpositive log-axis observation")
                ax.errorbar([r["capacity"] for r in rr],y,
                    yerr=[[r["median"]-r["minimum"] for r in rr],[r["maximum"]-r["median"] for r in rr]],
                    color=("#0072B2", "#555555")[index], marker=("o","s")[index],
                    linestyle=("-","--")[index], markersize=4, capsize=2,
                    linewidth=1, label=labels[series])
            ax.set(xlabel=f"({chr(97+panel)}) Capacity N",ylabel=ylabel,xticks=[4,8,16])
            if logarithmic: ax.set_yscale("log")
            else: ax.set_ylim(bottom=0)
            ax.grid(axis="y",alpha=.18);ax.spines[["top","right"]].set_visible(False)
            ax.legend(fontsize=7.4,frameon=False,loc="upper center")
        if validation_only:
            fig.text(.5,.01,"LOCAL PIPELINE VALIDATION — NOT PAPER MEASUREMENTS",ha="center",fontsize=8,color="#9c2626")
        for extension in ("pdf","svg","png"):
            fig.savefig(out/(name+"."+extension),dpi=300)
        plt.close(fig)


def write_inline_figures(summary, out):
    """Emit vector drawing code for a self-contained four-file LaTeX delivery.

    These coordinates use the identical audited summary as the PDF figures.
    No external data/figure paths, shell execution or unmeasured values are used.
    Text inherits the official manuscript font; standalone PDFs use Times.
    """
    specs = {
        "lifecycle": [("initialization", "Initialization (s)", True), ("updates_and_acquisitions", "Withdrawals and acquisitions (s)", True)],
        "helper": [("directory_update", "Directory update (ms)", False), ("client_helper_update", "Receiver helper update (ms)", False)],
        "transport": [("transport_A_first", "First output + new entry (MiB)", True), ("transport_A_fresh_repeat", "Repeated output (MiB)", True)],
        "service": [("service_execution", "Service execution (ms)", False), ("service_serialized_messages", "Serialized messages (MiB)", False)],
    }
    names={"CHARE":"CHARE", "DH-explicit-list":"DH (public list)", "delta":"Delta / cached", "rebuild":"Rebuild", "full":"Full context", "reference":"Exact reference", "cycle":"Cycle", "tree":"Tree"}
    for figure, panels in specs.items():
        lines=["% Generated by plot_paper_study.py from audited native observations.",
               r"\begingroup", r"\definecolor{evalblue}{HTML}{0072B2}",
               r"\begin{tikzpicture}",
               r"\begin{groupplot}[group style={group size=2 by 1,horizontal sep=1.35cm},",
               r"width=7.65cm,height=5.15cm,axis lines=left,xtick={4,8,16},",
               r"tick label style={font=\fontsize{8}{9}\selectfont},label style={font=\fontsize{8}{9}\selectfont},",
               r"legend style={draw=none,fill=none,font=\fontsize{7.5}{9}\selectfont},",
               r"grid=major,grid style={black!10},scaled y ticks=false]"]
        for panel,(metric,ylabel,log) in enumerate(panels):
            opts=(f"xlabel={{({chr(97+panel)}) Capacity $N$}},ylabel={{{ylabel}}},"
                  "legend style={at={(0.5,0.98)},anchor=north}")
            opts += ",ymode=log" if log else ",ymin=0"
            lines.append(r"\nextgroupplot["+opts+"]")
            data=[r for r in summary if r["metric"]==metric]
            for i,series in enumerate(sorted({r["series"] for r in data})):
                rows=sorted((r for r in data if r["series"]==series),key=lambda r:r["capacity"])
                style=("evalblue,mark=*,solid","black!65,mark=square*,dashed")[i]
                lines.append(r"\addplot["+style+r",mark size=1.6pt,line width=0.7pt,error bars/.cd,y dir=both,y explicit] coordinates {")
                for r in rows:
                    lines.append(f"({r['capacity']},{r['median']:.12g}) += (0,{r['maximum']-r['median']:.12g}) -= (0,{r['median']-r['minimum']:.12g})")
                lines += ["};",r"\addlegendentry{"+names[series]+"}"]
        lines += [r"\end{groupplot}",r"\end{tikzpicture}",r"\endgroup"]
        (out/("figure_"+figure+".tex")).write_text("\n".join(lines)+"\n",encoding="utf-8")


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run",type=Path)
    ap.add_argument("--output",type=Path,default=Path(__file__).resolve().parent/"output"/"paper-study")
    ap.add_argument("--validation-only",action="store_true",help="Label test pipeline figures; never integrate them into the paper")
    args=ap.parse_args()
    records,accounting,checks,manifest,provenance=collect(args.run,args.validation_only)
    summary=summarize(records)
    out=args.output/args.run.resolve().name;out.mkdir(parents=True,exist_ok=True)
    write_csv(out/"observations.csv",records);write_csv(out/"summary.csv",summary)
    write_csv(out/"accounting.csv",accounting)
    (out/"checks.json").write_text(json.dumps(checks,indent=2),encoding="utf-8")
    draw(summary,out,args.validation_only)
    if not args.validation_only: write_inline_figures(summary,out)
    (out/"provenance.json").write_text(json.dumps(dict(analysis_version=VERSION,source_run=str(args.run.resolve()),
        manifest=manifest,validation_only=args.validation_only,**provenance,
        aggregation="Sum distinct executed intervals within each independent case, then median and observed min/max over three cases; no confidence interval or significance test.",
        width_inches=7.04,height_inches=2.48,
        exclusions="Lifecycle excludes separately measured native admission, parameter generation, policy/transport/stress, service setup and study branches. Complete raw ledger retained. Service panels exclude shared two-generation issuance, owner key setup, coefficient audit and diagnostic recovery; separate accounting rows charge each. Plan construction bytes are recorded, but its time is not isolated; it is included only in case walltime alongside functional checks. Zero-duration plan/payload rows are byte observations, not zero-cost timing samples.",
        communication="Serialized objects only, no network timing. Cold reference includes actual entry+packet for one receiver; N installations separately retained. Warm view cannot stand for total deployment cost.",
        comparison="DH requires an externally given public authorized list. Native RIPE is functional core only. No equal-security speedup inferred."),indent=2),encoding="utf-8")
    print(out)


if __name__=="__main__": main()
