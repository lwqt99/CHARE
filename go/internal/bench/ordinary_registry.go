package bench

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Nik-U/pbc"
	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

// The explicit-list service receives already decided public authorization
// lists. It does not derive them from hidden records or issuer secrets.
// This is a specified lifecycle for the existing ordinary source-DH baseline,
// not a second hidden-qualification construction.
type policySpec struct {
	name string
	lits []core.Literal
}

type ordinarySigned struct{ message, signature []byte }

func (s ordinarySigned) wire() []byte {
	return auth.Frame("DH/independent-registry/signed/v1", s.message, s.signature)
}

type ordinaryMember struct {
	slot int
	key  []byte
}

type ordinaryView struct {
	policy  string // complete canonical policy bytes, not a digest
	version uint64
	members []ordinaryMember
	signed  ordinarySigned
}

type ordinaryEpoch struct {
	sequence uint64
	versions map[string]uint64
	signed   ordinarySigned
}

type ordinaryRetained struct {
	cipher  *OrdinaryCipher
	key     []byte
	slot    int
	context []byte
}

type ordinaryRegistry struct {
	ctx       *core.Context
	base      *core.Params // only Ctx, N, G; no CHARE CRS or projection arrays
	context   []byte
	scope     string // authenticated history namespace; stress branches are distinct
	authority *auth.Signer
	roots     []*core.Root // only Params, Slot, Q; never passed to CHARE validators
	secrets   []*core.UserSecret
	certs     []ordinarySigned
	order     []string
	views     map[string]*ordinaryView
	epoch     *ordinaryEpoch
	history   [][]byte
	transport transportState
	retained  []ordinaryRetained
}

func ordinaryPolicyKey(lits []core.Literal) string {
	fields := make([][]byte, 0, 2*len(lits))
	for _, lit := range lits {
		sign := byte(0)
		if lit.Negative {
			sign = 1
		}
		fields = append(fields, number(uint64(lit.Basis)), []byte{sign})
	}
	return string(auth.Frame("DH/fixed-policy/v1", fields...))
}

func newOrdinaryRegistry(ctx *core.Context, g *pbc.Element, n, attributes int, parameterText string, policies []policySpec) (*ordinaryRegistry, error) {
	if ctx == nil || g == nil || g.Pairing() != ctx.Pairing || g.Is0() || n < 1 || attributes < 1 || len(policies) == 0 {
		return nil, errors.New("DH registry: invalid group or policy inventory")
	}
	signer, err := auth.Generate()
	if err != nil {
		return nil, err
	}
	d := &ordinaryRegistry{ctx: ctx, base: &core.Params{Ctx: ctx, N: n, G: ctx.Pairing.NewG1().Set(g)}, authority: signer, scope: "main",
		roots: make([]*core.Root, n), secrets: make([]*core.UserSecret, n), certs: make([]ordinarySigned, n), views: make(map[string]*ordinaryView)}
	seen := make(map[string]bool)
	for _, spec := range policies {
		for _, lit := range spec.lits {
			if lit.Basis < 0 || lit.Basis >= attributes {
				return nil, errors.New("DH registry: unknown policy position")
			}
		}
		key := ordinaryPolicyKey(spec.lits)
		if seen[key] {
			return nil, errors.New("DH registry: duplicate policy")
		}
		seen[key] = true
		d.order = append(d.order, key)
	}
	fields := [][]byte{[]byte(parameterText), ctx.P.Bytes(), g.Bytes(), number(uint64(n)), number(uint64(attributes)), signer.Public()}
	for _, key := range d.order {
		fields = append(fields, []byte(key))
	}
	d.context = auth.Frame("DH/independent-registry/context/v1", fields...)
	return d, nil
}

func (d *ordinaryRegistry) keygen(slot int) error {
	if slot < 0 || slot >= len(d.roots) || d.roots[slot] != nil {
		return errors.New("DH registry: invalid or occupied slot")
	}
	z, err := d.ctx.Sample(true)
	if err != nil {
		return err
	}
	d.roots[slot] = &core.Root{Params: d.base, Slot: slot, Q: d.ctx.SourceScale(d.base.G, z)}
	d.secrets[slot] = &core.UserSecret{Params: d.base, Slot: slot, Z: z}
	return nil
}

func (d *ordinaryRegistry) certMessage(slot int) ([]byte, error) {
	if slot < 0 || slot >= len(d.roots) || d.roots[slot] == nil || d.roots[slot].Q == nil || d.roots[slot].Q.Is0() {
		return nil, errors.New("DH registry: missing reception key")
	}
	r := d.roots[slot]
	if r.Params != d.base || r.Slot != slot || r.Q.Pairing() != d.ctx.Pairing {
		return nil, errors.New("DH registry: wrong key context")
	}
	return auth.Frame("DH/independent-registry/certificate/v1", d.context, number(uint64(slot)), number(1), r.Q.Bytes()), nil
}

func (d *ordinaryRegistry) certify(slot int) error {
	message, err := d.certMessage(slot)
	if err != nil {
		return err
	}
	if d.certs[slot].message != nil {
		return errors.New("DH registry: immutable key already certified")
	}
	d.certs[slot] = ordinarySigned{message: message, signature: d.authority.Sign(message)}
	return nil
}

func (d *ordinaryRegistry) verifyCertificate(slot int) error {
	message, err := d.certMessage(slot)
	if err != nil {
		return err
	}
	s := d.certs[slot]
	if !bytes.Equal(message, s.message) || !auth.Verify(d.authority.Public(), s.message, s.signature) {
		return errors.New("DH registry: certificate binding or signature")
	}
	return nil
}

func (d *ordinaryRegistry) registryBytes() []byte {
	fields := [][]byte{d.context}
	for _, cert := range d.certs {
		fields = append(fields, cert.wire())
	}
	return auth.Frame("DH/independent-registry/directory/v1", fields...)
}

func (d *ordinaryRegistry) viewMessage(v *ordinaryView) []byte {
	// The epoch and each view must bind the same history namespace. Otherwise
	// two genuine views with equal local versions can be swapped across forks.
	fields := [][]byte{d.context, []byte(d.scope), []byte(v.policy), number(v.version)}
	for _, member := range v.members {
		fields = append(fields, number(uint64(member.slot)), member.key)
	}
	return auth.Frame("DH/independent-registry/authorization/v2", fields...)
}

func (d *ordinaryRegistry) epochMessage(e *ordinaryEpoch) []byte {
	fields := [][]byte{d.context, []byte(d.scope), number(e.sequence)}
	for _, policy := range d.order {
		fields = append(fields, []byte(policy), number(e.versions[policy]))
	}
	return auth.Frame("DH/independent-registry/epoch/v1", fields...)
}

// publish is atomic for rejected public input and uses only public lists/keys
// and the authority's signing key. Unchanged lists retain their local version.
// The global signed epoch binds the complete ordered policy-version map.
func (d *ordinaryRegistry) publish(sequence uint64, lists map[string][]int) ([]byte, error) {
	if len(lists) != len(d.order) || (d.epoch != nil && sequence <= d.epoch.sequence) {
		return nil, errors.New("DH registry: wrong inventory or nonincreasing epoch")
	}
	views := make(map[string]*ordinaryView, len(d.order))
	epoch := &ordinaryEpoch{sequence: sequence, versions: make(map[string]uint64, len(d.order))}
	var changed [][]byte
	for _, policy := range d.order {
		ids, ok := lists[policy]
		if !ok {
			return nil, errors.New("DH registry: missing fixed policy")
		}
		v := &ordinaryView{policy: policy, version: 1}
		previous := -1
		for _, slot := range ids {
			if slot < 0 || slot >= len(d.roots) || slot <= previous || d.roots[slot] == nil || d.certs[slot].message == nil {
				return nil, errors.New("DH registry: noncanonical or uncertified member")
			}
			previous = slot
			v.members = append(v.members, ordinaryMember{slot, append([]byte(nil), d.roots[slot].Q.Bytes()...)})
		}
		old := d.views[policy]
		if old != nil {
			v.version = old.version
			if bytes.Equal(d.viewMessage(v), old.signed.message) {
				views[policy] = old
				epoch.versions[policy] = old.version
				continue
			}
			if v.version == ^uint64(0) {
				return nil, errors.New("DH registry: policy version overflow")
			}
			v.version++
		}
		v.signed.message = d.viewMessage(v)
		v.signed.signature = d.authority.Sign(v.signed.message)
		views[policy] = v
		epoch.versions[policy] = v.version
		changed = append(changed, v.signed.wire())
	}
	epoch.signed.message = d.epochMessage(epoch)
	epoch.signed.signature = d.authority.Sign(epoch.signed.message)
	d.views, d.epoch = views, epoch
	publication := auth.Frame("DH/independent-registry/publication/v1", append([][]byte{epoch.signed.wire()}, changed...)...)
	d.history = append(d.history, append([]byte(nil), publication...))
	return publication, nil
}

func (d *ordinaryRegistry) verifyEpoch(e *ordinaryEpoch, expected uint64) error {
	if e == nil || e.sequence != expected || len(e.versions) != len(d.order) {
		return errors.New("DH registry: wrong expected epoch")
	}
	for _, policy := range d.order {
		if e.versions[policy] == 0 {
			return errors.New("DH registry: missing policy version")
		}
	}
	if !bytes.Equal(e.signed.message, d.epochMessage(e)) || !auth.Verify(d.authority.Public(), e.signed.message, e.signed.signature) {
		return errors.New("DH registry: epoch authentication")
	}
	return nil
}

func (d *ordinaryRegistry) verifyView(v *ordinaryView, e *ordinaryEpoch, expected uint64) error {
	if err := d.verifyEpoch(e, expected); err != nil {
		return err
	}
	if v == nil || v.version == 0 || e.versions[v.policy] != v.version {
		return errors.New("DH registry: stale or foreign policy version")
	}
	previous := -1
	for _, member := range v.members {
		if member.slot <= previous || member.slot < 0 || member.slot >= len(d.roots) || len(member.key) == 0 {
			return errors.New("DH registry: malformed member list")
		}
		previous = member.slot
	}
	if !bytes.Equal(v.signed.message, d.viewMessage(v)) || !auth.Verify(d.authority.Public(), v.signed.message, v.signed.signature) {
		return errors.New("DH registry: authorization authentication")
	}
	return nil
}

// selectedRoots is a SENDER operation against its acquired public registry.
// Receiver authentication uses verifyView and does not need others' secrets
// or a free copy of all other users' certificates.
func (d *ordinaryRegistry) selectedRoots(v *ordinaryView) ([]*core.Root, error) {
	if v == nil {
		return nil, errors.New("DH registry: missing authorization")
	}
	selected := make([]*core.Root, len(v.members))
	for j, member := range v.members {
		if member.slot < 0 || member.slot >= len(d.roots) {
			return nil, errors.New("DH registry: member slot out of range")
		}
		r := d.roots[member.slot]
		if r == nil || !bytes.Equal(member.key, r.Q.Bytes()) {
			return nil, errors.New("DH registry: authorized root differs from acquired registry")
		}
		selected[j] = r
	}
	return selected, nil
}

func (d *ordinaryRegistry) acquire(slot int, expected uint64, initial bool) ([]byte, error) {
	if slot < 0 || slot >= len(d.roots) {
		return nil, errors.New("DH registry: wrong requesting slot")
	}
	if err := d.verifyEpoch(d.epoch, expected); err != nil {
		return nil, err
	}
	fields := [][]byte{d.epoch.signed.wire()}
	if initial {
		if err := d.verifyCertificate(slot); err != nil {
			return nil, err
		}
		if d.secrets[slot] == nil || d.secrets[slot].Z == nil {
			return nil, errors.New("DH registry: missing own secret")
		}
		own := d.ctx.SourceScale(d.base.G, d.secrets[slot].Z)
		if !own.Equals(d.roots[slot].Q) {
			return nil, errors.New("DH registry: own key mismatch")
		}
		fields = append(fields, d.certs[slot].wire(), d.authority.Public())
	}
	wire := auth.Frame("DH/independent-registry/acquisition/v1", fields...)
	return append([]byte(nil), wire...), nil
}

func (d *ordinaryRegistry) retainedBytes() int64 {
	var total int64
	for _, cert := range d.certs {
		total += int64(len(cert.wire()))
	}
	for _, wire := range d.history {
		total += int64(len(wire))
	}
	return total
}

func (d *ordinaryRegistry) verifyRetained() error {
	for k, item := range d.retained {
		got, err := OrdinaryDec(d.ctx, item.cipher, d.secrets[item.slot], item.context)
		if err != nil || !bytes.Equal(got, item.key) {
			return fmt.Errorf("DH retained ciphertext %d: %v", k, err)
		}
	}
	return nil
}
