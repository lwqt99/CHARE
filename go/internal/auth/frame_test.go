package auth_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"example.org/chare/internal/auth"
)

func TestFrameWireFormat(t *testing.T) {
	// Version prefix, a one-byte domain D, two fields, {00,ff}, and an empty field.
	want, err := hex.DecodeString(
		"43484152452d415554482d4652414d450001" +
			"000000000000000144" +
			"0000000000000002" +
			"000000000000000200ff" +
			"0000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	got := auth.Frame("D", []byte{0, 255}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire-format mismatch\ngot  %x\nwant %x", got, want)
	}
}

func TestFrameSeparatesBoundariesCountsAndDomains(t *testing.T) {
	frames := [][]byte{
		auth.Frame("D", []byte("ab"), []byte("c")),
		auth.Frame("D", []byte("a"), []byte("bc")),
		auth.Frame("D", []byte("abc")),
		auth.Frame("D", []byte("abc"), nil),
		auth.Frame("D"),
		auth.Frame("D", nil),
		auth.Frame("D\x00", []byte("abc")),
		auth.Frame("", []byte("Dabc")),
	}
	for i := range frames {
		for j := 0; j < i; j++ {
			if bytes.Equal(frames[i], frames[j]) {
				t.Fatalf("ambiguous frames %d and %d", i, j)
			}
		}
	}
	if !bytes.Equal(auth.Frame("D", nil), auth.Frame("D", []byte{})) {
		t.Fatal("nil and empty byte strings should denote the same field")
	}
}

func TestFrameOwnsFieldBytes(t *testing.T) {
	field := []byte("record")
	framed := auth.Frame("D", field)
	want := append([]byte(nil), framed...)
	field[0] ^= 1
	if !bytes.Equal(framed, want) {
		t.Fatal("caller mutation changed framed bytes")
	}
	framed[0] ^= 1
	if !bytes.Equal(auth.Frame("D", []byte("record")), want) {
		t.Fatal("result mutation changed subsequent frames")
	}
}
