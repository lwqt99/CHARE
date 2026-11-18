package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// CHAREPrefix returns the actual serialized prefix through the immutable
// target context and literal count. It excludes the literal coordinates,
// fresh weights, and both ciphertext points. Same-length policies under one
// fixed prepared state/binding reuse this entry. Parsing checks framing only,
// not group membership, scalar validity, or the cryptographic statement.
func CHAREPrefix(full []byte) ([]byte, error) {
	r := reader{b: full}
	fields := make([][]byte, 6)
	contextStart := 0
	for i := range fields {
		value, start, err := r.field()
		if err != nil {
			return nil, err
		}
		fields[i] = value
		if i == 3 {
			contextStart = start
		}
	}
	if r.pos != len(full) || string(fields[0]) != "ciphertext" || len(fields[1]) != 32 || len(fields[2]) != 8 || len(fields[4]) == 0 || len(fields[5]) == 0 {
		return nil, errors.New("transport: invalid CHARE frame")
	}
	c := reader{b: fields[3]}
	base := make([][]byte, 6)
	for i := range base {
		value, _, err := c.field()
		if err != nil {
			return nil, err
		}
		base[i] = value
	}
	if string(base[0]) != "CHARE-RATIONAL-CORE-v1/target" || !bytes.Equal(base[3], fields[1]) || !bytes.Equal(base[4], fields[2]) || len(base[5]) != 8 {
		return nil, errors.New("transport: inconsistent CHARE target frame")
	}
	prefixEnd := contextStart + c.pos
	count := binary.BigEndian.Uint64(base[5])
	if count > uint64(len(c.b)-c.pos)/24 {
		return nil, errors.New("transport: impossible literal count")
	}
	for i := uint64(0); i < count; i++ {
		index, _, e1 := c.field()
		sign, _, e2 := c.field()
		weight, _, e3 := c.field()
		if e1 != nil || e2 != nil || e3 != nil || len(index) != 8 || len(sign) != 1 || sign[0] > 1 || len(weight) == 0 {
			return nil, errors.New("transport: invalid literal framing")
		}
	}
	if c.pos != len(c.b) {
		return nil, errors.New("transport: trailing target bytes")
	}
	return append([]byte(nil), full[:prefixEnd]...), nil
}

// DHPrefix applies the same exact-prefix adapter to the actual shorter DH
// context. No CHARE record or helper is added to the DH baseline. The fresh
// head, public recipient list, anchor and wraps remain in every packet.
func DHPrefix(full []byte) ([]byte, error) {
	_, ends, err := readFrame(full, "CHARE/ordinary-dh/ciphertext/v1", 5)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), full[:ends[0]]...), nil
}
