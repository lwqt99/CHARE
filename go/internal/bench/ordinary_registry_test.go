package bench

import (
	"bytes"
	"testing"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
)

func registryFixture(t *testing.T) *ordinaryRegistry {
	t.Helper()
	ctx, err := core.NewContext(deliveryFunctionalParams)
	if err != nil {
		t.Fatal(err)
	}
	g := ctx.Pairing.NewG1().Rand()
	for tries := 1; g.Is0() && tries < 1024; tries++ {
		g.Rand()
	}
	if g.Is0() {
		t.Fatal("test generator sampling failed")
	}
	d, err := newOrdinaryRegistry(ctx, g, 4, 2, deliveryFunctionalParams, []policySpec{
		{"A", []core.Literal{{Basis: 0}}}, {"B", []core.Literal{{Basis: 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range d.roots {
		if err = d.keygen(i); err != nil {
			t.Fatal(err)
		}
		if err = d.certify(i); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func registryLists(d *ordinaryRegistry, a, b []int) map[string][]int {
	return map[string][]int{d.order[0]: a, d.order[1]: b}
}

func TestIndependentRegistryKeysAndCertificates(t *testing.T) {
	d := registryFixture(t)
	for slot, root := range d.roots {
		if root.V != nil || d.secrets[slot].V != nil || len(root.Proj) != 0 {
			t.Fatal("explicit-list registry unexpectedly uses CHARE core material")
		}
		if err := d.verifyCertificate(slot); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.keygen(0); err == nil {
		t.Fatal("immutable key overwritten")
	}
	original := d.roots[0].Q
	d.roots[0].Q = d.ctx.SourceAdd(original, d.base.G)
	if err := d.verifyCertificate(0); err == nil {
		t.Fatal("certificate accepted a different reception key")
	}
	d.roots[0].Q = original
	d.roots[0].Slot = 1
	if err := d.verifyCertificate(0); err == nil {
		t.Fatal("certificate accepted another slot")
	}
	d.roots[0].Slot = 0
	d.certs[0].signature[0] ^= 1
	if err := d.verifyCertificate(0); err == nil {
		t.Fatal("certificate accepted altered signature")
	}
}

func TestRegistryPartialRevocationAndFreshness(t *testing.T) {
	d := registryFixture(t)
	if _, err := d.publish(0, registryLists(d, []int{1, 3}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	oldA, oldB, oldEpoch := d.views[d.order[0]], d.views[d.order[1]], d.epoch
	if _, err := d.acquire(3, 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.publish(1, registryLists(d, []int{1}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	if d.views[d.order[1]] != oldB || d.views[d.order[0]].version != oldA.version+1 {
		t.Fatal("changed and unchanged local versions not separated")
	}
	if err := d.verifyView(oldB, d.epoch, 1); err != nil {
		t.Fatal("valid B was invalidated by A revocation", err)
	}
	if d.verifyView(oldA, d.epoch, 1) == nil || d.verifyEpoch(oldEpoch, 1) == nil || d.verifyEpoch(d.epoch, 0) == nil {
		t.Fatal("stale view or wrong trusted expected epoch accepted")
	}
	if _, err := d.acquire(3, 1, false); err != nil {
		t.Fatal(err)
	}
	// The receiver checks only public state; another holder's secret is absent.
	saved := d.secrets[2]
	d.secrets[2] = nil
	if err := d.verifyView(oldB, d.epoch, 1); err != nil {
		t.Fatal("verification unexpectedly needs another holder secret", err)
	}
	d.secrets[2] = saved
	foreign := registryFixture(t)
	if err := foreign.verifyEpoch(d.epoch, 1); err == nil {
		t.Fatal("cross-registry signed epoch accepted")
	}
}

func TestRegistryRejectsInvalidInputAtomically(t *testing.T) {
	d := registryFixture(t)
	if _, err := d.publish(4, registryLists(d, []int{1}, []int{2})); err != nil {
		t.Fatal(err)
	}
	before, history := d.epoch, len(d.history)
	for _, invalid := range [][]int{{1, 1}, {2, 1}, {-1}, {4}} {
		// A changes first: a later invalid B must not partially publish A.
		if _, err := d.publish(5, registryLists(d, []int{3}, invalid)); err == nil {
			t.Fatal("invalid list accepted")
		}
		if d.epoch != before || len(d.history) != history || d.views[d.order[0]].members[0].slot != 1 {
			t.Fatal("failed publication changed public state")
		}
	}
	if _, err := d.publish(4, registryLists(d, nil, nil)); err == nil {
		t.Fatal("nonincreasing epoch accepted")
	}
	if _, err := d.publish(5, map[string][]int{d.order[0]: nil}); err == nil {
		t.Fatal("missing fixed policy accepted")
	}
	old := d.views[d.order[0]]
	old.version = ^uint64(0)
	old.signed.message = d.viewMessage(old)
	old.signed.signature = d.authority.Sign(old.signed.message)
	if _, err := d.publish(5, registryLists(d, []int{3}, []int{2})); err == nil {
		t.Fatal("local version wraparound accepted")
	}
	if _, err := d.selectedRoots(&ordinaryView{members: []ordinaryMember{{slot: 4, key: []byte{1}}}}); err == nil {
		t.Fatal("out-of-range member not rejected")
	}
}

func TestRegistryEmptyListsOldStateAndRegrant(t *testing.T) {
	d := registryFixture(t)
	if _, err := d.publish(0, registryLists(d, []int{1, 3}, nil)); err != nil {
		t.Fatal(err)
	}
	view := d.views[d.order[0]]
	selected, err := d.selectedRoots(view)
	if err != nil {
		t.Fatal(err)
	}
	context := auth.Frame("test-old-context", d.epoch.signed.wire(), view.signed.wire())
	ct, key, err := OrdinaryEnc(d.ctx, d.base.G, selected, context)
	if err != nil {
		t.Fatal(err)
	}
	d.retained = append(d.retained, ordinaryRetained{ct, key, 3, context})
	if _, err = d.publish(1, registryLists(d, nil, nil)); err != nil {
		t.Fatal(err)
	}
	empty := d.views[d.order[0]]
	if err = d.verifyView(empty, d.epoch, 1); err != nil || len(empty.members) != 0 {
		t.Fatal("empty state invalid", err)
	}
	if _, _, err = OrdinaryEnc(d.ctx, d.base.G, nil, context); err == nil {
		t.Fatal("empty anchored KEM ran")
	}
	if err = d.verifyRetained(); err != nil {
		t.Fatal(err)
	}
	if _, err = d.publish(2, registryLists(d, []int{3}, nil)); err != nil {
		t.Fatal(err)
	}
	if d.views[d.order[0]].version != 3 || len(d.history) != 3 {
		t.Fatal("regrant did not preserve immutable history and version")
	}
	selected, err = d.selectedRoots(d.views[d.order[0]])
	if err != nil {
		t.Fatal(err)
	}
	newContext := auth.Frame("test-new-context", d.epoch.signed.wire(), d.views[d.order[0]].signed.wire())
	fresh, want, err := OrdinaryEnc(d.ctx, d.base.G, selected, newContext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OrdinaryDec(d.ctx, fresh, d.secrets[3], newContext)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("regrant key did not round trip", err)
	}
	if err = d.verifyRetained(); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryTamperAndBranchIsolation(t *testing.T) {
	d := registryFixture(t)
	if _, err := d.publish(0, registryLists(d, []int{1, 3}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	view := d.views[d.order[0]]
	view.members[0].key[0] ^= 1
	if err := d.verifyView(view, d.epoch, 0); err == nil {
		t.Fatal("modified member key accepted")
	}
	view.members[0].key[0] ^= 1
	branch := *d
	branch.scope = "test-branch"
	branch.history = nil
	if _, err := branch.publish(1, registryLists(d, []int{3}, []int{3})); err != nil {
		t.Fatal(err)
	}
	if d.epoch.sequence != 0 || len(d.history) != 1 || len(d.views[d.order[0]].members) != 2 {
		t.Fatal("branch modified main state")
	}
	if d.verifyEpoch(branch.epoch, 1) == nil || branch.verifyEpoch(branch.epoch, 1) != nil {
		t.Fatal("branch authentication scope is not enforced")
	}
	d.epoch.versions[d.order[0]]++
	if d.verifyEpoch(d.epoch, 0) == nil {
		t.Fatal("altered version map accepted")
	}
}

func TestRegistryRejectsEqualVersionViewFromAnotherHistory(t *testing.T) {
	d := registryFixture(t)
	if _, err := d.publish(0, registryLists(d, []int{1, 3}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	branch := *d
	branch.scope = "other-selected-history"
	branch.history = nil
	if _, err := branch.publish(1, registryLists(d, []int{3}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	if _, err := d.publish(1, registryLists(d, []int{1}, []int{2, 3})); err != nil {
		t.Fatal(err)
	}
	policy := d.order[0]
	if d.views[policy].version != branch.views[policy].version {
		t.Fatal("fixture lacks equal local versions")
	}
	if err := d.verifyView(d.views[policy], d.epoch, 1); err != nil {
		t.Fatal(err)
	}
	if err := branch.verifyView(branch.views[policy], branch.epoch, 1); err != nil {
		t.Fatal(err)
	}
	if d.verifyView(branch.views[policy], d.epoch, 1) == nil {
		t.Fatal("foreign view accepted under genuine main epoch with equal version")
	}
	if branch.verifyView(d.views[policy], branch.epoch, 1) == nil {
		t.Fatal("main view accepted under genuine branch epoch with equal version")
	}
}
