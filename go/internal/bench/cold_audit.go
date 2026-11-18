package bench

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

const ColdAuditProfile = "typed-public-history-replay-v1"

// Pins and the expected sequence come from the existing trusted setup/current
// snapshot interfaces. All remaining inputs are public generated typed objects.
// No secret, signer, truth label, directory moment cache or mutable row table is
// available to this verifier. This is not an untrusted network point decoder.
type coldPublicInput struct {
	params                    *core.Params
	roots                     []*core.Root
	rootWires, rootSignatures [][]byte
	authority                 ed25519.PublicKey
	issuers                   []ed25519.PublicKey
	history                   []*issued
	sequence                  uint64
	snapshot, signature       []byte
	help                      *core.HelpBundle
}

type ColdAuditEntry struct {
	Scheme   string `json:"scheme"`
	Slot     int    `json:"slot"`
	Sequence uint64 `json:"sequence"`
	Bytes    int64  `json:"bytes"`
}

type ColdAuditEvidence struct {
	Profile string           `json:"profile"`
	Clients int              `json:"clients"`
	Entries []ColdAuditEntry `json:"entries"`
}

func (in *coldPublicInput) metadata(a, slot int, r *issued) []byte {
	return auth.Frame("CHARE/issuance-context/v1", []byte(ProtocolVersion), in.params.Bytes(), number(uint64(a)), number(uint64(slot)), number(r.version), number(1), number(^uint64(0)), in.rootWires[slot], r.row.Bytes())
}

// Verify every historical record before replaying it. The replay reproduces
// the initial ID, immutable generation order, append-only context and version;
// simply rebuilding current rows would not reproduce those identities.
func verifyColdPublic(in *coldPublicInput, client int) ([]byte, error) {
	if in == nil || in.params == nil || in.help == nil {
		return nil, errors.New("cold audit: missing public input")
	}
	n, m := len(in.roots), len(in.issuers)
	if n != in.params.N || m < 1 || client < 0 || client >= n || in.help.Slot != client || len(in.rootWires) != n || len(in.rootSignatures) != n || in.sequence > uint64(len(in.history)) || uint64(len(in.history)) != uint64(n)*uint64(m)+in.sequence {
		return nil, errors.New("cold audit: incomplete roster, history or client")
	}
	if !auth.Verify(in.authority, in.snapshot, in.signature) {
		return nil, errors.New("cold audit: unauthenticated snapshot")
	}
	for slot, root := range in.roots {
		if root == nil || root.Slot != slot {
			return nil, errors.New("cold audit: wrong root slot")
		}
		msg := auth.Frame("CHARE/authorized-root/v1", []byte(ProtocolVersion), in.params.Bytes(), number(uint64(slot)), root.Bytes())
		if !auth.Verify(in.authority, msg, in.rootSignatures[slot]) || !bytes.Equal(in.rootWires[slot], auth.Frame("CHARE/certified-root/v1", msg, in.rootSignatures[slot], in.authority)) {
			return nil, errors.New("cold audit: root certificate binding")
		}
		if err := core.ValidateRoot(in.params, root); err != nil {
			return nil, err
		}
	}
	rows := make([][]*core.Row, m)
	current := make([][]*issued, m)
	for a := range rows {
		rows[a] = make([]*core.Row, n)
		current[a] = make([]*issued, n)
	}
	var rebuilt *core.Prepared
	for index, r := range in.history {
		if r == nil || r.row == nil || r.delivery == nil || r.row.Slot < 0 || r.row.Slot >= n {
			return nil, errors.New("cold audit: malformed historical record")
		}
		slot, a := r.row.Slot, -1
		// Namespace recovery uses public injectively framed metadata, not a
		// qualification oracle or the holder's decryption secret.
		for candidate := range in.issuers {
			if bytes.Equal(r.metadata, in.metadata(candidate, slot, r)) {
				a = candidate
				break
			}
		}
		if a < 0 {
			return nil, errors.New("cold audit: historical metadata mismatch")
		}
		if err := core.ValidateRow(in.params, in.roots[slot], r.row); err != nil {
			return nil, err
		}
		if err := ValidateDelivery(in.params.Ctx, in.params.G, in.roots[slot].Q, r.delivery, r.metadata, in.issuers[a]); err != nil {
			return nil, err
		}
		if index < n*m {
			if a != index/n || slot != index%n || r.version != 1 {
				return nil, errors.New("cold audit: initial generation order/version")
			}
		} else {
			if current[a][slot] == nil || r.version <= current[a][slot].version {
				return nil, errors.New("cold audit: historical rollback/replay")
			}
			if err := rebuilt.UpdateRow(a, slot, r.row); err != nil {
				return nil, err
			}
		}
		rows[a][slot], current[a][slot] = r.row, r
		if index == n*m-1 {
			var err error
			rebuilt, err = core.AggregateValidated(in.params, in.roots, rows)
			if err != nil {
				return nil, err
			}
		}
	}
	if rebuilt == nil || rebuilt.Version != in.sequence {
		return nil, errors.New("cold audit: wrong replay endpoint")
	}
	fields := [][]byte{[]byte(ProtocolVersion), in.params.Bytes(), number(in.sequence), number(uint64(n)), number(uint64(m)), rebuilt.VerifierBytes(), rebuilt.SenderBytes()}
	fields = append(fields, in.rootWires...)
	for _, key := range in.issuers {
		fields = append(fields, key)
	}
	for a := range current {
		for _, r := range current[a] {
			fields = append(fields, r.publicBytes())
		}
	}
	if !bytes.Equal(in.snapshot, auth.Frame("CHARE/full-current-snapshot/v2", fields...)) {
		return nil, errors.New("cold audit: signed aggregate differs from independent history replay")
	}
	if err := core.VerifyHelp(rebuilt, in.help); err != nil {
		return nil, err
	}
	// Include all actually required public history and the supplied helper.
	// Duplication already present in the full snapshot is not silently removed.
	wireFields := [][]byte{in.snapshot, in.signature}
	for _, r := range in.history {
		wireFields = append(wireFields, r.publicBytes())
	}
	wireFields = append(wireFields, in.help.Bytes())
	wire := auth.Frame("CHARE/independent-cold-audit/v1", wireFields...)
	return append([]byte(nil), wire...), nil
}

func (w *workload) coldInput(snapshot, signature []byte, h *core.HelpBundle) *coldPublicInput {
	keys := make([]ed25519.PublicKey, len(w.issuers))
	for a, signer := range w.issuers {
		keys[a] = signer.Public()
	}
	return &coldPublicInput{params: w.pp, roots: w.roots, rootWires: w.rootBytes, rootSignatures: w.rootSignatures,
		authority: w.rootAuthority, issuers: keys, history: w.history, sequence: w.sequence,
		snapshot: snapshot, signature: signature, help: h}
}

func (w *workload) coldAudits(cfg Config, snapshot, signature []byte) error {
	clients, mode := 1, "stress_one_client_replay"
	if cfg.ColdAuditAllUsers {
		clients, mode = cfg.Capacity, "stress_all_clients_replay"
	}
	e := &ColdAuditEvidence{Profile: ColdAuditProfile, Clients: clients}
	w.result.ColdAudit = e
	for slot := 0; slot < clients; slot++ {
		if err := w.measure("CHARE", "cold_audit", mode, 1, func() (int64, error) {
			h, err := core.Help(w.prepared, slot)
			if err != nil {
				return 0, err
			}
			wire, err := verifyColdPublic(w.coldInput(snapshot, signature, h), slot)
			if err != nil {
				return 0, err
			}
			e.Entries = append(e.Entries, ColdAuditEntry{"CHARE", slot, w.sequence, int64(len(wire))})
			return int64(len(wire)), nil
		}); err != nil {
			return err
		}
		w.result.Measurements[len(w.result.Measurements)-1].Detail += fmt.Sprintf(";cold_client_slot=%d;cold_sequence=%d", slot, w.sequence)
		if err := w.ordinaryColdAudit(slot, mode, e); err != nil {
			return err
		}
		w.result.Measurements[len(w.result.Measurements)-1].Detail += fmt.Sprintf(";cold_client_slot=%d;cold_sequence=%d", slot, w.sequence)
	}
	if err := ValidateColdAuditEvidence(cfg, e); err != nil {
		return err
	}
	return w.check("independent_cold_audit_completed", true, fmt.Sprintf("%d actual clients per scheme; CHARE independently replayed every public generation; no multiplied timing", clients))
}

func ValidateColdAuditEvidence(cfg Config, e *ColdAuditEvidence) error {
	want := 1
	if cfg.ColdAuditAllUsers {
		want = cfg.Capacity
	}
	if e == nil || e.Profile != ColdAuditProfile || e.Clients != want || len(e.Entries) != 2*want {
		return errors.New("cold audit: incomplete evidence")
	}
	seen := make(map[string]bool)
	for _, entry := range e.Entries {
		key := fmt.Sprintf("%s/%d", entry.Scheme, entry.Slot)
		if (entry.Scheme != "CHARE" && entry.Scheme != "DH-explicit-list") || entry.Slot < 0 || entry.Slot >= want || entry.Sequence != uint64(cfg.Revocations) || entry.Bytes <= 0 || seen[key] {
			return errors.New("cold audit: duplicate/missing client or wrong endpoint")
		}
		seen[key] = true
	}
	return nil
}
