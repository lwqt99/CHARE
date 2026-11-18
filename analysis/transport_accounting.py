"""Audit actual v0.6.0/v0.6.1 cache measurements; no generated timings or wire traffic.

The ledger distinguishes serialized outputs, actual entry acquisitions and local
expanded bytes. It does not turn encoding a packet into an observed network send.
"""
from collections import defaultdict

VERSION = "chare-exact-transport-accounting-v1"
SUPPORTED = {"chare-go-pbc-v0.6.0", "chare-go-pbc-v0.6.1", "chare-go-pbc-v0.6.2", "chare-go-pbc-v0.7.0"}
NUMERIC = ("duration_ns", "bytes", "source_ops", "pairings", "count")
PER_PACKET = ("transport_prefix_prepare", "transport_registry_lookup",
              "transport_packet_encode", "transport_packet_expand")
REPEAT = ("transport_repeat_encapsulate", "transport_repeat_help", "transport_repeat_decapsulate")
OTHER = ("transport_cache_setup", "transport_entry_publish", "transport_entry_install", "transport_retained_bytes")
KNOWN = set(PER_PACKET + REPEAT + OTHER)
FRAME_PREFIX = b"CHARE-AUTH-FRAME\x00\x01"


def frame_overhead(domain, count):
    return len(FRAME_PREFIX) + 16 + len(domain.encode("ascii")) + 8 * count


PACKET_FRAME = frame_overhead("CHARE/exact-prefix-packet/v1", 2)
ENTRY_FRAME = frame_overhead("CHARE/exact-prefix-entry/v1", 3)


def policy_modes(config):
    policies = ["A", "not_A"]
    if config["attributes"] >= 2:
        policies += ["B", "A_and_B"]
    if config["attributes"] > 2:
        policies += ["all_attributes"]
    return policies + ["after_updates_" + p for p in policies]


def phase(mode):
    if mode == "cold":
        return "cache_setup"
    if mode.startswith("stress_"):
        return "stress"
    return "main_after_updates" if mode.startswith("after_updates_") else "main_initial"


def _values(row):
    out = {}
    for key in NUMERIC:
        value = row[key]
        if isinstance(value, bool) or not str(value).isdigit():
            raise ValueError(f"Invalid transport measurement {key}: {value!r}")
        out[key] = int(value)
    if out["count"] != 1:
        raise ValueError("Each audited transport interval must be one actual execution")
    if row["operation"] == "transport_retained_bytes":
        if out["duration_ns"] or "no timing sample" not in row["detail"]:
            raise ValueError("Retained-byte observations are not timing samples")
    elif "no timing sample" in row["detail"]:
        raise ValueError("A transport operation lacks an actual timed interval")
    return out


def transport_ledgers(case, config, rows, checks, version):
    """Return packet, phase and coverage views of the SAME original rows.

    Earlier schemas are deliberately not given v0.6.0 validation or zero costs.
    Call after normal file/checksum/case validation. Consistency is not authenticity.
    """
    if version not in SUPPORTED:
        return [], [], []
    n = config["capacity"]
    dims = {"case_id": case, **config}
    selected = []
    for index, row in enumerate(rows):
        if not row["operation"].startswith("transport_"):
            continue
        if row["operation"] not in KNOWN:
            raise ValueError("Unknown transport operation, accounting map needs review")
        scheme = row["scheme"]
        if scheme == "CHARE-auth" and row["operation"] == "transport_cache_setup":
            scheme = "CHARE"
        if scheme not in {"CHARE", "DH-explicit-list"}:
            raise ValueError("Unexpected transport scheme")
        selected.append({**row, **_values(row), "scheme": scheme, "row_index": index})
    grouped = defaultdict(list)
    for row in selected:
        grouped[(row["scheme"], row["mode"], row["operation"])].append(row)

    def one(scheme, mode, operation, required=True):
        rr = grouped.get((scheme, mode, operation), [])
        if len(rr) != 1 and (required or rr):
            raise ValueError(f"Missing/duplicated transport row: {scheme}/{mode}/{operation}")
        return rr[0] if rr else None

    main = policy_modes(config)
    stress = ["stress_changed_cohort_A", "stress_regrant_A"]
    coverage = []
    expected_transfers = set()
    for scheme in ["CHARE", "DH-explicit-list"]:
        setup = one(scheme, "cold", "transport_cache_setup")
        if setup["bytes"] != 32:
            raise ValueError("Pinned Ed25519 public-key size differs from audited source")
        for mode in ["publisher_buffer_contents", "one_client_buffer_contents"]:
            one(scheme, mode, "transport_retained_bytes")
        for mode in main + stress:
            # CHARE instruments main policies only. DH additionally instruments
            # its regrant branch; changed-cohort transport is off for both.
            instrumented = mode in main or (scheme == "DH-explicit-list" and mode == "stress_regrant_A") or (version == "chare-go-pbc-v0.7.0" and config.get("paper_study") and scheme == "CHARE" and mode in stress)
            empty = [c for c in checks if c["name"] == mode + "/DH-empty-list"] if scheme == "DH-explicit-list" else []
            if empty and (len(empty) != 1 or empty[0]["passed"] is not True):
                raise ValueError("Invalid empty-list outcome evidence")
            first = [r for r in rows if (r["scheme"], r["operation"], r["mode"]) == (scheme, "encapsulate", mode)]
            if empty and first:
                raise ValueError("Empty DH list cannot also have an anchored encapsulation")
            if instrumented and not empty:
                if len(first) != 1 or int(first[0]["count"]) != 1:
                    raise ValueError(f"Missing first real encapsulation for {scheme}/{mode}")
                status = "executed"
                expected_transfers.update((scheme, mode + "/" + kind) for kind in ["first", "fresh_repeat"])
            elif empty:
                status = "empty_authorized_list_no_encapsulation"
            else:
                status = "transport_not_instrumented_for_this_branch"
            coverage.append({**dims, "scheme": scheme, "mode": mode, "phase": phase(mode),
                             "status": status, "transport_instrumented": instrumented,
                             "empty_authorized_list": bool(empty),
                             "comparison_is_same_hidden_functionality": False})

    actual_transfers = {(r["scheme"], r["mode"]) for r in selected if r["operation"] == "transport_prefix_prepare"}
    if actual_transfers != expected_transfers:
        raise ValueError("Transport coverage differs from source policy/empty-list schedule")
    allowed_keys = set()
    for scheme in ["CHARE", "DH-explicit-list"]:
        allowed_keys.add((scheme, "cold", "transport_cache_setup"))
        for mode in ["publisher_buffer_contents", "one_client_buffer_contents"]:
            allowed_keys.add((scheme, mode, "transport_retained_bytes"))

    packets = []
    for scheme, mode in sorted(expected_transfers):
        base, kind = mode.rsplit("/", 1)
        rr = {op: one(scheme, mode, op) for op in PER_PACKET}
        publication = one(scheme, mode, "transport_entry_publish", required=False)
        installs = grouped.get((scheme, mode, "transport_entry_install"), [])
        expected_order = list(PER_PACKET[:2])
        if publication:
            if kind != "first" or len(installs) != n:
                raise ValueError("Each actual new entry needs N separate installs; repeats cannot republish")
            if any(r["bytes"] != publication["bytes"] for r in installs):
                raise ValueError("Installed wire size differs from the actual published entry")
            expected_order += ["transport_entry_publish"] + ["transport_entry_install"] * n
        elif installs:
            raise ValueError("Entry installation without an actual new publication")
        expected_order += list(PER_PACKET[2:])
        seq = [r for r in selected if r["scheme"] == scheme and r["mode"] == mode]
        if [r["operation"] for r in seq] != expected_order:
            raise ValueError("Transport trace has missing, duplicate or reordered operations")
        for r in seq:
            allowed_keys.add((scheme, mode, r["operation"]))

        p = rr["transport_prefix_prepare"]["bytes"]
        packet = rr["transport_packet_encode"]["bytes"]
        full = rr["transport_packet_expand"]["bytes"]
        overhead = packet - (full - p)
        id_bytes = overhead - PACKET_FRAME
        if p <= 0 or full <= p or id_bytes <= 0 or rr["transport_registry_lookup"]["bytes"] != 0:
            raise ValueError("Invalid exact-prefix/full/packet byte identity")
        # Seal's wire is Frame(entryDomain,id,prefix,64-byte signature).
        if publication and publication["bytes"] != ENTRY_FRAME + id_bytes + p + 64:
            raise ValueError("Signed-entry framing does not match measured packet ID/prefix lengths")
        original_op = "encapsulate" if kind == "first" else "transport_repeat_encapsulate"
        original = [r for r in rows if (r["scheme"],r["operation"],r["mode"]) == (scheme,original_op,base)]
        if len(original) != 1 or int(original[0]["count"]) != 1 or int(original[0]["bytes"]) != full:
            raise ValueError("Expanded bytes do not match the actual corresponding full ciphertext")
        _values(original[0])
        packets.append({**dims, "scheme": scheme, "mode": mode, "policy_mode": base,
                        "phase": phase(base), "kind": kind,
                        "full_ciphertext_bytes": full, "prefix_bytes": p,
                        "packet_output_bytes": packet, "packet_framing_and_id_bytes": overhead,
                        "id_length_from_frame": id_bytes,
                        "new_publication": publication is not None,
                        "publication_output_bytes": publication["bytes"] if publication else 0,
                        "actual_installations": len(installs),
                        "client_installation_bytes": sum(r["bytes"] for r in installs),
                        "adapter_measured_interval_ns": sum(r["duration_ns"] for r in seq),
                        "zero_duration_rows": sum(r["duration_ns"] == 0 for r in seq),
                        "network_transmissions_measured": False})

    by_packet = {(r["scheme"],r["mode"]):r for r in packets}
    executed = {(s, mode.rsplit("/", 1)[0]) for s, mode in expected_transfers}
    for scheme, base in executed:
        first, repeat = (by_packet[(scheme, base + "/" + k)] for k in ["first", "fresh_repeat"])
        for field in ["full_ciphertext_bytes", "prefix_bytes", "packet_framing_and_id_bytes"]:
            if first[field] != repeat[field]:
                raise ValueError("Fresh repeat changed the fixed-target serialization layout")
        if repeat["new_publication"]:
            raise ValueError("Fresh repeat is not a cache hit")
        for op in REPEAT:
            if scheme == "DH-explicit-list" and op == "transport_repeat_help":
                continue
            one(scheme, base, op)
            allowed_keys.add((scheme, base, op))
    if set(grouped) != allowed_keys:
        raise ValueError("Unaccounted transport rows or duplicated context")

    phases = []
    for scheme in ["CHARE", "DH-explicit-list"]:
        for name in ["cache_setup", "main_initial", "main_after_updates", "stress"]:
            rr = [r for r in selected if r["scheme"] == scheme and r["operation"] != "transport_retained_bytes" and phase(r["mode"]) == name]
            if not rr:
                continue
            pp = [r for r in packets if r["scheme"] == scheme and r["phase"] == name]
            adapter = [r for r in rr if r["operation"] not in REPEAT]
            repeat = [r for r in rr if r["operation"] in REPEAT]
            def total(op, field="bytes"):
                return sum(r[field] for r in rr if r["operation"] == op)
            phases.append({**dims, "scheme": scheme, "phase": name,
                           "observed_packet_outputs": len(pp),
                           "actual_publications": total("transport_entry_publish", "count"),
                           "actual_installations": total("transport_entry_install", "count"),
                           "setup_key_output_bytes": total("transport_cache_setup"),
                           "publication_output_bytes": total("transport_entry_publish"),
                           "client_installation_bytes": total("transport_entry_install"),
                           "packet_output_bytes": total("transport_packet_encode"),
                           "paired_full_ciphertext_bytes": sum(r["full_ciphertext_bytes"] for r in pp),
                           "local_expansion_bytes": total("transport_packet_expand"),
                           "prefix_materialization_bytes": total("transport_prefix_prepare"),
                           "adapter_measured_interval_ns": sum(r["duration_ns"] for r in adapter),
                           "repeat_crypto_measured_interval_ns": sum(r["duration_ns"] for r in repeat),
                           "adapter_source_ops": sum(r["source_ops"] for r in adapter),
                           "adapter_pairings": sum(r["pairings"] for r in adapter),
                           "repeat_source_ops": sum(r["source_ops"] for r in repeat),
                           "repeat_pairings": sum(r["pairings"] for r in repeat),
                           "zero_duration_rows": sum(r["duration_ns"] == 0 for r in rr),
                           "also_in_lifecycle_exclusions": True})
    return packets, phases, coverage
