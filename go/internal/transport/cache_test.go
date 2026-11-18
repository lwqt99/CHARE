package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"example.org/chare/internal/auth"
)

func fixture(t *testing.T) (*auth.Signer, *Cache) {
	t.Helper()
	s, err := auth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCache(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func TestExactRoundTripAndOwnership(t *testing.T) {
	s, c := fixture(t)
	id, prefix := []byte("epoch-7"), []byte{0, 1, 2, 255}
	entry, err := Seal(s, id, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Install(id, entry); err != nil {
		t.Fatal(err)
	}
	if err = c.Install(id, entry); err != nil {
		t.Fatal("exact replay", err)
	}
	prefix[0] = 99
	entry[len(entry)-1] ^= 1
	for _, suffix := range [][]byte{nil, {0, 255, 7}, bytes.Repeat([]byte{8}, 4096)} {
		full := append([]byte{0, 1, 2, 255}, suffix...)
		packet, e := Encode(id, full[:4], full)
		if e != nil {
			t.Fatal(e)
		}
		restored, e := c.Expand(id, packet)
		if e != nil || !bytes.Equal(restored, full) {
			t.Fatal("not exact", e)
		}
		restored[0] = 99
		again, e := c.Expand(id, packet)
		if e != nil || !bytes.Equal(again, full) {
			t.Fatal("cache alias", e)
		}
	}
}

func TestAuthenticationConflictAndExpectedVersion(t *testing.T) {
	s, c := fixture(t)
	other, _ := fixture(t)
	id := []byte("epoch-1")
	entry, _ := Seal(s, id, []byte("prefix"))
	if err := c.Install(id, entry); err != nil {
		t.Fatal(err)
	}
	bad, _ := Seal(other, id, []byte("prefix"))
	conflict, _ := Seal(s, id, []byte("different"))
	for _, b := range [][]byte{bad, conflict} {
		if c.Install(id, b) == nil {
			t.Fatal("invalid entry accepted")
		}
	}
	if c.Install([]byte("epoch-2"), entry) == nil {
		t.Fatal("wrong epoch accepted")
	}
	packet, _ := Encode(id, []byte("prefix"), []byte("prefix-body"))
	if _, err := c.Expand([]byte("epoch-2"), packet); err == nil {
		t.Fatal("old packet accepted as current")
	}
	_, empty := fixture(t)
	if _, err := empty.Expand(id, packet); err == nil {
		t.Fatal("missing entry accepted")
	}
	if _, err := Encode(id, []byte("wrong"), []byte("prefix-body")); err == nil {
		t.Fatal("mismatched prefix accepted")
	}
	if _, err := NewCache(nil); err == nil {
		t.Fatal("empty publisher accepted")
	}
}

func TestMalformedPacketsAndSuffixScope(t *testing.T) {
	s, c := fixture(t)
	id := []byte("id")
	entry, _ := Seal(s, id, []byte("P"))
	if err := c.Install(id, entry); err != nil {
		t.Fatal(err)
	}
	packet, _ := Encode(id, []byte("P"), []byte("P-body"))
	for i := 0; i < len(packet); i++ {
		if _, err := c.Expand(id, packet[:i]); err == nil {
			t.Fatalf("truncation %d", i)
		}
	}
	for i := 0; i < len(entry); i++ {
		if c.Install(id, entry[:i]) == nil {
			t.Fatalf("entry truncation %d", i)
		}
	}
	badLength := append([]byte(nil), packet...)
	header := len(auth.Frame(packetDomain))
	binary.BigEndian.PutUint64(badLength[header:header+8], ^uint64(0))
	for _, b := range [][]byte{append(append([]byte(nil), packet...), 0), badLength, auth.Frame("wrong", id, []byte("-body")), auth.Frame(packetDomain, []byte("-body"), id), auth.Frame(packetDomain, id)} {
		if _, err := c.Expand(id, b); err == nil {
			t.Fatal("malformed packet accepted")
		}
	}
	// Suffixes remain unauthenticated CPA ciphertext material. Expansion must
	// NOT pretend a changed suffix has passed the original cryptographic checks.
	changed := auth.Frame(packetDomain, id, []byte("changed"))
	out, err := c.Expand(id, changed)
	if err != nil || string(out) != "Pchanged" {
		t.Fatal(err)
	}
}

func coreFrame(fields ...[]byte) []byte {
	var out []byte
	for _, b := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(b)))
		out = append(out, b...)
	}
	return out
}
func u64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }
func chareWire(index, weight byte, version uint64) []byte {
	id := bytes.Repeat([]byte{3}, 32)
	context := coreFrame([]byte("CHARE-RATIONAL-CORE-v1/target"), []byte("large dictionary"), []byte("signed snapshot"), id, u64(version), u64(1), u64(uint64(index)), []byte{0}, []byte{weight})
	return coreFrame([]byte("ciphertext"), id, u64(version), context, []byte("point0"), []byte("point1"))
}

func TestCHAREPrefixExcludesFreshPolicyWeights(t *testing.T) {
	x, y := chareWire(0, 4, 1), chareWire(1, 5, 1)
	px, err := CHAREPrefix(x)
	if err != nil {
		t.Fatal(err)
	}
	py, err := CHAREPrefix(y)
	if err != nil || !bytes.Equal(px, py) {
		t.Fatal("unreusable prefix", err)
	}
	z, _ := CHAREPrefix(chareWire(0, 4, 2))
	if bytes.Equal(px, z) {
		t.Fatal("version not bound")
	}
	s, c := fixture(t)
	id := []byte("test")
	entry, _ := Seal(s, id, px)
	if err = c.Install(id, entry); err != nil {
		t.Fatal(err)
	}
	for _, wire := range [][]byte{x, y} {
		packet, e := Encode(id, px, wire)
		if e != nil {
			t.Fatal(e)
		}
		back, e := c.Expand(id, packet)
		if e != nil || !bytes.Equal(back, wire) {
			t.Fatal(e)
		}
	}
	for i := 0; i < len(x); i++ {
		if _, e := CHAREPrefix(x[:i]); e == nil {
			t.Fatalf("truncation %d", i)
		}
	}
	if _, err = CHAREPrefix(append(x, 0)); err == nil {
		t.Fatal("trailing bytes")
	}
}

func TestDHPrefixUsesItsOwnContext(t *testing.T) {
	makeWire := func(head string) []byte {
		return auth.Frame("CHARE/ordinary-dh/ciphertext/v1", []byte("short own context"), []byte(head), u64(0), []byte("list"), []byte("wraps"))
	}
	x, y := makeWire("head1"), makeWire("head2")
	p, err := DHPrefix(x)
	if err != nil {
		t.Fatal(err)
	}
	q, err := DHPrefix(y)
	if err != nil || !bytes.Equal(p, q) {
		t.Fatal("fresh head retained", err)
	}
	if _, err = DHPrefix(append(x, 0)); err == nil {
		t.Fatal("trailing bytes")
	}
	if _, err = CHAREPrefix(x); err == nil {
		t.Fatal("cross format")
	}
}
