package core

import (
	"bytes"
	"math/big"
	"runtime"
	"runtime/debug"
	"testing"
)

// Stress temporary native operand ownership while Go finalizers are running.
// Only this goroutine uses PBC; the collector goroutine performs no group work.
// This is a native-wrapper regression, not a security or timing experiment.
func TestNativeGCChainedOperations(t *testing.T) {
	previous := debug.SetGCPercent(10)
	defer debug.SetGCPercent(previous)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	c, err := NewContext(largeFunctionalParams)
	if err != nil {
		t.Fatal(err)
	}
	pp, err := Setup(c, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		a := new(big.Int).Sub(c.P, big.NewInt(int64(i+3)))
		b := big.NewInt(int64(i + 11))
		left := c.Pair(c.SourceScale(c.clone(pp.G), a), c.SourceScale(c.clone(pp.H), b))
		right := c.TargetScale(c.Pair(pp.G, pp.H), c.mul(a, b))
		if !left.Equals(right) {
			t.Fatalf("bilinearity with temporary operands failed at iteration %d", i)
		}
		original := c.SourceScale(pp.G, a)
		serialized := original.Bytes()
		copied := c.Pairing.NewG1().SetBytes(serialized)
		if !copied.Equals(original) || !bytes.Equal(copied.Bytes(), serialized) {
			t.Fatalf("native element round trip failed at iteration %d", i)
		}
		root, _, err := UserKeyGen(pp, i%8)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRoot(pp, root); err != nil {
			t.Fatalf("root iteration %d: %v", i, err)
		}
		row, _, err := Issue(pp, root, i%2 == 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateRow(pp, root, row); err != nil {
			t.Fatalf("row iteration %d: %v", i, err)
		}
	}
}
