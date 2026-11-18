package core

import (
	"bytes"
	"testing"
)

func TestNativeHelpDeltaMatchesReconstruction(t *testing.T) {
	for _, n := range []int{2, 4, 8} {
		f := newFixture(t, n)
		for changed := 0; changed < n; changed++ {
			next, _, err := Issue(f.pp, f.roots[changed], false)
			if err != nil {
				t.Fatal(err)
			}
			staged := make([]*HelpBundle, n)
			for receiver := 0; receiver < n; receiver++ {
				old, e := Help(f.agg, receiver)
				if e != nil {
					t.Fatal(e)
				}
				before := old.Bytes()
				oldContext := f.agg.ContextBytes()
				staged[receiver], e = HelpDelta(f.agg, old, 0, changed, next)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(before, old.Bytes()) || !bytes.Equal(oldContext, f.agg.ContextBytes()) {
					t.Fatal("staging mutated original state")
				}
				if receiver == changed && !old.Parts[1].Equals(staged[receiver].Parts[1]) {
					t.Fatal("own-slot helper changed")
				}
			}
			if err = f.agg.UpdateRow(0, changed, next); err != nil {
				t.Fatal(err)
			}
			for receiver := 0; receiver < n; receiver++ {
				full, e := Help(f.agg, receiver)
				if e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(full.Bytes(), staged[receiver].Bytes()) {
					t.Fatalf("N=%d changed=%d receiver=%d", n, changed, receiver)
				}
				if e = VerifyHelp(f.agg, staged[receiver]); e != nil {
					t.Fatal(e)
				}
				if _, e = HelpDelta(f.agg, staged[receiver], 0, changed, nil); e == nil {
					t.Fatal("nil new record accepted")
				}
			}
		}
	}
}

func TestNativeHelpDeltaRejectsBindingsAndLastProjection(t *testing.T) {
	f := newFixture(t, 4)
	old, _ := Help(f.agg, 0)
	next, _, _ := Issue(f.pp, f.roots[1], true)
	bad := cloneRow(next)
	bad.F[len(bad.F)-1] = f.pp.Ctx.SourceAdd(bad.F[len(bad.F)-1], f.pp.G)
	if _, e := HelpDelta(f.agg, old, 0, 1, bad); e == nil {
		t.Fatal("unchecked last projection")
	}
	if _, e := HelpDelta(f.agg, old, 0, 2, next); e == nil {
		t.Fatal("wrong changed slot")
	}
	if _, e := HelpDelta(f.agg, old, 2, 1, next); e == nil {
		t.Fatal("wrong basis")
	}
	if e := f.agg.UpdateRow(0, 1, next); e != nil {
		t.Fatal(e)
	}
	if _, e := HelpDelta(f.agg, old, 0, 1, next); e == nil {
		t.Fatal("stale helper")
	}
	other, err := Aggregate(f.pp, f.roots[:3], [][]*Row{f.rows[0][:3], f.rows[1][:3]})
	if err != nil {
		t.Fatal(err)
	}
	if _, e := HelpDelta(other, old, 0, 1, next); e == nil {
		t.Fatal("cross-cohort helper")
	}
}
