package bench

import (
	"bytes"
	"errors"
	"fmt"

	"example.org/chare/internal/auth"
	"example.org/chare/internal/core"
	"example.org/chare/internal/transport"
)

type cachedEntry struct{ prefix, wire []byte }
type transportState struct {
	signer  *auth.Signer
	client  *transport.Cache
	entries map[string]cachedEntry
}

// observeTransport is an additional, separately labelled transport profile.
// Every entry is signed and installed/verified once per real client. To avoid
// modelling all N machines in one process, only the first client's cache is
// retained; the other installations actually execute, then release their RAM.
// Thus process peak RSS is NOT the sum of all clients' retained cache storage.
func (w *workload) observeTransport(scheme, mode string, id []byte, serialize func() []byte) error {
	state := &w.transport
	if scheme == "DH-explicit-list" {
		if w.ordinary == nil {
			return errors.New("independent DH transport registry not initialized")
		}
		state = &w.ordinary.transport
	} else if scheme != "CHARE" {
		return errors.New("unknown transport scheme")
	}
	var full, prefix []byte
	if err := w.measure(scheme, "transport_prefix_prepare", mode, 1, func() (int64, error) {
		full = serialize()
		var err error
		if scheme == "CHARE" {
			prefix, err = transport.CHAREPrefix(full)
		} else {
			prefix, err = transport.DHPrefix(full)
		}
		return int64(len(prefix)), err
	}); err != nil {
		return err
	}
	var entry cachedEntry
	if err := w.measure(scheme, "transport_registry_lookup", mode, 1, func() (int64, error) {
		entry = state.entries[string(id)]
		if entry.wire != nil && !bytes.Equal(entry.prefix, prefix) {
			return 0, errors.New("conflicting cached prefix under immutable ID")
		}
		return 0, nil
	}); err != nil {
		return err
	}
	if entry.wire == nil {
		if err := w.measure(scheme, "transport_entry_publish", mode, 1, func() (int64, error) {
			wire, err := transport.Seal(state.signer, id, prefix)
			if err != nil {
				return 0, err
			}
			entry = cachedEntry{append([]byte(nil), prefix...), wire}
			state.entries[string(id)] = entry
			return int64(len(wire)), nil
		}); err != nil {
			return err
		}
		for slot := range w.roots {
			if err := w.measure(scheme, "transport_entry_install", mode, 1, func() (int64, error) {
				client := state.client
				if slot != 0 {
					var err error
					client, err = transport.NewCache(state.signer.Public())
					if err != nil {
						return 0, err
					}
				}
				received := append([]byte(nil), entry.wire...)
				return int64(len(received)), client.Install(id, received)
			}); err != nil {
				return err
			}
		}
	}
	var packet, restored []byte
	if err := w.measure(scheme, "transport_packet_encode", mode, 1, func() (int64, error) {
		var err error
		packet, err = transport.Encode(id, entry.prefix, full)
		return int64(len(packet)), err
	}); err != nil {
		return err
	}
	if err := w.measure(scheme, "transport_packet_expand", mode, 1, func() (int64, error) {
		var err error
		restored, err = state.client.Expand(id, packet)
		return int64(len(restored)), err
	}); err != nil {
		return err
	}
	return w.check(fmt.Sprintf("%s/%s/exact_transport", scheme, mode), bytes.Equal(restored, full), "original serialized bytes restored exactly; generated typed objects used for PBC, no untrusted point decoder claimed")
}

func (w *workload) chareTransport(name string, target *core.Target, first *core.Ciphertext) error {
	return w.chareTransportAt(name, target, first, w.prepared)
}

func (w *workload) chareTransportAt(name string, target *core.Target, first *core.Ciphertext, prepared *core.Prepared) error {
	id := auth.Frame("CHARE/transport-reference/v1", []byte("CHARE"), target.PreparedID[:], number(target.Version), number(uint64(len(target.Policy))))
	if err := w.observeTransport("CHARE", name+"/first", id, first.Bytes); err != nil {
		return err
	}
	var second *core.Ciphertext
	var key []byte
	if err := w.measure("CHARE", "transport_repeat_encapsulate", name, 1, func() (int64, error) {
		var err error
		second, key, err = core.Encapsulate(target)
		if err != nil {
			return 0, err
		}
		return int64(len(second.Bytes())), nil
	}); err != nil {
		return err
	}
	if err := w.observeTransport("CHARE", name+"/fresh_repeat", id, second.Bytes); err != nil {
		return err
	}
	// Check a genuinely fresh encapsulation, choosing a qualified receiver when
	// one exists. This is a functional test, not a cryptographic security game.
	slot := prepared.Slots[0]
	for _, i := range prepared.Slots {
		if w.qualifies(i, target.Policy) {
			slot = i
			break
		}
	}
	var help *core.HelpBundle
	if err := w.measure("CHARE", "transport_repeat_help", name, 1, func() (int64, error) {
		var err error
		help, err = core.Help(prepared, slot)
		if err != nil {
			return 0, err
		}
		return int64(len(help.Bytes())), core.VerifyHelp(prepared, help)
	}); err != nil {
		return err
	}
	var got []byte
	if err := w.measure("CHARE", "transport_repeat_decapsulate", name, 1, func() (int64, error) {
		var err error
		got, err = core.Decapsulate(target, second, w.secrets[slot], w.ownMasks(slot), help)
		return int64(len(got)), err
	}); err != nil {
		return err
	}
	return w.check(name+"/fresh_repeat/CHARE", bytes.Equal(got, key) == w.qualifies(slot, target.Policy), "fresh full-domain encapsulation; same frozen target, original KDF and contexts")
}

func (w *workload) dhTransport(name string, first *OrdinaryCipher, allowed []*core.Root, context []byte) error {
	id := auth.Frame("DH/transport-reference/v1", w.ordinary.context, []byte(w.ordinary.scope), number(w.sequence), []byte(name))
	if err := w.observeTransport("DH-explicit-list", name+"/first", id, func() []byte { return OrdinaryBytes(first) }); err != nil {
		return err
	}
	var second *OrdinaryCipher
	var key, got []byte
	if err := w.measure("DH-explicit-list", "transport_repeat_encapsulate", name, 1, func() (int64, error) {
		var err error
		second, key, err = OrdinaryEnc(w.ctx, w.ordinary.base.G, allowed, context)
		if err != nil {
			return 0, err
		}
		return int64(len(OrdinaryBytes(second))), nil
	}); err != nil {
		return err
	}
	if err := w.observeTransport("DH-explicit-list", name+"/fresh_repeat", id, func() []byte { return OrdinaryBytes(second) }); err != nil {
		return err
	}
	if err := w.measure("DH-explicit-list", "transport_repeat_decapsulate", name, 1, func() (int64, error) {
		var err error
		got, err = OrdinaryDec(w.ctx, second, w.ordinary.secrets[allowed[0].Slot], context)
		return int64(len(got)), err
	}); err != nil {
		return err
	}
	return w.check(name+"/fresh_repeat/DH", bytes.Equal(got, key), "same transport option with independent DH keys, authority and authenticated explicit-list context")
}

func (w *workload) transportStorage(scheme string, state *transportState) {
	var publisherBytes int64
	for id, entry := range state.entries {
		publisherBytes += int64(len(id)) + int64(len(entry.prefix)) + int64(len(entry.wire))
	}
	w.result.Measurements = append(w.result.Measurements,
		Measurement{Scheme: scheme, Operation: "transport_retained_bytes", Mode: "publisher_buffer_contents", Bytes: publisherBytes, Count: 1, Detail: "no timing sample; actual ID/prefix/signed-entry buffers including duplicates; excludes object/map overhead and signer"},
		Measurement{Scheme: scheme, Operation: "transport_retained_bytes", Mode: "one_client_buffer_contents", Bytes: state.client.RetainedBytes(), Count: 1, Detail: "no timing sample; actual pinned key/ID/prefix buffers; one retained client, not N-client peak RSS; excludes object/map overhead"})
}
