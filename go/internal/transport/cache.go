// Package transport is an exact-byte transport adapter, not a new KEM or
// untrusted PBC point decoder. A pinned publisher authenticates immutable
// prefixes; receivers restore the ORIGINAL full ciphertext before using it.
// Currentness and the expected cache ID must come from the caller's trusted
// snapshot logic. Authentication does not establish absence of forks.
package transport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"example.org/chare/internal/auth"
)

const (
	entryDomain  = "CHARE/exact-prefix-entry/v1"
	bindDomain   = "CHARE/exact-prefix-binding/v1"
	packetDomain = "CHARE/exact-prefix-packet/v1"
)

// Seal signs the literal ID and prefix. There is no extra digest substituted
// for the original context. The returned wire entry includes the signature.
func Seal(signer *auth.Signer, id, prefix []byte) ([]byte, error) {
	if signer == nil || len(id) == 0 || len(prefix) == 0 {
		return nil, errors.New("transport: empty publisher, ID, or prefix")
	}
	sig := signer.Sign(auth.Frame(bindDomain, id, prefix))
	return auth.Frame(entryDomain, id, prefix, sig), nil
}

type Cache struct {
	public   ed25519.PublicKey
	prefixes map[string][]byte
}

// RetainedBytes counts the actual pinned key, ID and prefix byte contents.
// It excludes map/object overhead and is not an operating-system RSS metric.
func (c *Cache) RetainedBytes() int64 {
	if c == nil {
		return 0
	}
	n := int64(len(c.public))
	for id, prefix := range c.prefixes {
		n += int64(len(id)) + int64(len(prefix))
	}
	return n
}

// NewCache pins an independently trusted publisher key. The cache is local,
// append-only, and not safe for concurrent mutation. Limit inbound message
// sizes and cache capacity at the application boundary in network deployments.
func NewCache(public ed25519.PublicKey) (*Cache, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("transport: invalid pinned key")
	}
	return &Cache{append(ed25519.PublicKey(nil), public...), make(map[string][]byte)}, nil
}

// Install validates every received entry, even an exact replay. It rejects
// both a wrong expected ID and a conflicting prefix under an installed ID.
func (c *Cache) Install(expectedID, wire []byte) error {
	f, _, err := readFrame(wire, entryDomain, 3)
	if err != nil {
		return err
	}
	if c == nil || len(expectedID) == 0 || !bytes.Equal(f[0], expectedID) || len(f[1]) == 0 {
		return errors.New("transport: wrong installation context")
	}
	if !auth.Verify(c.public, auth.Frame(bindDomain, f[0], f[1]), f[2]) {
		return errors.New("transport: entry authentication failed")
	}
	id := string(f[0])
	if old, ok := c.prefixes[id]; ok {
		if !bytes.Equal(old, f[1]) {
			return errors.New("transport: conflicting immutable entry")
		}
		return nil
	}
	c.prefixes[id] = append([]byte(nil), f[1]...)
	return nil
}

// Encode checks the actual prefix and emits only the ID and remaining bytes.
// This scan and suffix copy are real work, not a constant-time KEM operation.
func Encode(id, prefix, full []byte) ([]byte, error) {
	if len(id) == 0 || len(prefix) == 0 || !bytes.HasPrefix(full, prefix) {
		return nil, errors.New("transport: full ciphertext does not extend prefix")
	}
	return auth.Frame(packetDomain, id, full[len(prefix):]), nil
}

// Expand restores exact bytes, requiring the caller's expected immutable ID.
// It does not authenticate the suffix or claim CCA security. Its output is
// still subject to the original protocol's parsing and validation rules.
func (c *Cache) Expand(expectedID, packet []byte) ([]byte, error) {
	f, _, err := readFrame(packet, packetDomain, 2)
	if err != nil {
		return nil, err
	}
	if c == nil || len(expectedID) == 0 || !bytes.Equal(f[0], expectedID) {
		return nil, errors.New("transport: wrong ciphertext context")
	}
	prefix, ok := c.prefixes[string(f[0])]
	if !ok {
		return nil, errors.New("transport: missing authenticated prefix")
	}
	if len(prefix) > int(^uint(0)>>1)-len(f[1]) {
		return nil, errors.New("transport: expanded length overflow")
	}
	out := make([]byte, 0, len(prefix)+len(f[1]))
	out = append(out, prefix...)
	return append(out, f[1]...), nil
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) field() (value []byte, start int, err error) {
	if len(r.b)-r.pos < 8 {
		return nil, 0, errors.New("transport: truncated field length")
	}
	n := binary.BigEndian.Uint64(r.b[r.pos : r.pos+8])
	r.pos += 8
	if n > uint64(len(r.b)-r.pos) {
		return nil, 0, errors.New("transport: truncated field")
	}
	start = r.pos
	r.pos += int(n)
	return r.b[start:r.pos], start, nil
}

// readFrame accepts one exact auth.Frame domain and field count, with no
// trailing bytes. Lengths are bounded by actual input before integer casting.
func readFrame(wire []byte, domain string, count int) ([][]byte, []int, error) {
	template := auth.Frame(domain, make([][]byte, count)...)
	header := template[:len(template)-8*count]
	if !bytes.HasPrefix(wire, header) {
		return nil, nil, errors.New("transport: wrong frame domain/count")
	}
	r := reader{wire, len(header)}
	fields, ends := make([][]byte, count), make([]int, count)
	for i := range fields {
		value, _, err := r.field()
		if err != nil {
			return nil, nil, err
		}
		fields[i], ends[i] = value, r.pos
	}
	if r.pos != len(wire) {
		return nil, nil, errors.New("transport: trailing frame bytes")
	}
	return fields, ends, nil
}
