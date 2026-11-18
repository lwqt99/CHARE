package auth

import "encoding/binary"

// The fixed prefix selects this serialization version. Domain and field lengths
// are uint64 big-endian values; no hashing, truncation, or text normalization is
// performed here.
const framePrefix = "CHARE-AUTH-FRAME\x00\x01"

// Frame canonically frames one domain and an ordered list of byte strings:
//
//	version-prefix || len(domain) || domain || field-count ||
//	len(field[0]) || field[0] || ... || len(field[n-1]) || field[n-1]
//
// Every length and the field count occupies exactly eight big-endian bytes.
// The domain is its exact Go string bytes. Empty and nil byte slices denote the
// same empty field; an empty field is distinct from an absent field. Fields are
// copied into the result. Distinct domains, field boundaries, counts, orders, or
// contents have distinct frames. Callers supply any required integer encodings,
// parameter/holder/version identities, and authorization context as fields.
//
// This is an encoder, not a decoder or an input-validation substitute. Like
// ordinary Go slice construction, allocation can panic for an oversized input.
func Frame(domain string, fields ...[]byte) []byte {
	out := append([]byte(nil), framePrefix...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(domain)))
	out = append(out, domain...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(fields)))
	for _, field := range fields {
		out = binary.BigEndian.AppendUint64(out, uint64(len(field)))
		out = append(out, field...)
	}
	return out
}
