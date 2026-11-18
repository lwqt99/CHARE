package bench

import (
	"bytes"
	"testing"

	"example.org/chare/internal/core"
	"example.org/chare/internal/transport"
)

// Actual PBC serialization integration, executed by the VM's native test gate.
// No algebraic security property is inferred from this round trip.
func TestNativeCiphertextPrefixAdapter(t *testing.T) {
	ctx, pp, roots, _, signer := deliveryFixture(t)
	rows := make([]*core.Row, len(roots))
	for i, root := range roots {
		var err error
		rows[i], _, err = core.Issue(pp, root, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	agg, err := core.Aggregate(pp, roots, [][]*core.Row{rows})
	if err != nil {
		t.Fatal(err)
	}
	var savedPrefix []byte
	client, err := transport.NewCache(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	for i, negative := range []bool{false, true} {
		target, e := core.PrepareTargetWithContext(agg, []core.Literal{{Basis: 0, Negative: negative}}, []byte("same snapshot"))
		if e != nil {
			t.Fatal(e)
		}
		ct, _, e := core.Encapsulate(target)
		if e != nil {
			t.Fatal(e)
		}
		wire := ct.Bytes()
		prefix, e := transport.CHAREPrefix(wire)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			savedPrefix = prefix
			entry, e := transport.Seal(signer, []byte("CHARE-v1"), prefix)
			if e != nil {
				t.Fatal(e)
			}
			if e = client.Install([]byte("CHARE-v1"), entry); e != nil {
				t.Fatal(e)
			}
		} else if !bytes.Equal(prefix, savedPrefix) {
			t.Fatal("fresh weights/policy changed cached prefix")
		}
		packet, e := transport.Encode([]byte("CHARE-v1"), savedPrefix, wire)
		if e != nil {
			t.Fatal(e)
		}
		back, e := client.Expand([]byte("CHARE-v1"), packet)
		if e != nil || !bytes.Equal(back, wire) {
			t.Fatal(e)
		}
	}
	ct, _, err := OrdinaryEnc(ctx, pp.G, roots, []byte("own short context"))
	if err != nil {
		t.Fatal(err)
	}
	wire := OrdinaryBytes(ct)
	prefix, err := transport.DHPrefix(wire)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := transport.Seal(signer, []byte("DH-v1"), prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Install([]byte("DH-v1"), entry); err != nil {
		t.Fatal(err)
	}
	packet, err := transport.Encode([]byte("DH-v1"), prefix, wire)
	if err != nil {
		t.Fatal(err)
	}
	back, err := client.Expand([]byte("DH-v1"), packet)
	if err != nil || !bytes.Equal(back, wire) {
		t.Fatal(err)
	}
}
