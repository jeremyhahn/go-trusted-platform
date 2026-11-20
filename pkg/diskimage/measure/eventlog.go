// TCG2 event logs. A measured boot leaves a crypto-agile event log
// (binary_bios_measurements): a TCG_PCClientPCREvent header whose event is
// the Spec ID Event03 structure (TCG PC Client Platform Firmware Profile,
// the Spec ID event section), then one TCG_PCR_EVENT2 record per
// measurement (the profile's crypto-agile event section).
// ParseEventLog reads it, ReplayEventLog extends each PCR from its records,
// and CheckEventLog compares the replay with the banks Predict writes into
// an image's manifest, so a booted image proves the predicted values.

package measure

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// TCG PC Client PFP event types the boot chain logs.
const (
	EventNoAction                   = 0x3
	EventSeparator                  = 0x4
	EventTag                        = 0x6
	EventSCRTMVersion               = 0x8
	EventEFIVariableDriverConfig    = 0x80000001
	EventEFIBootServicesApplication = 0x80000003
	EventEFIAction                  = 0x80000007
	EventEFIVariableAuthority       = 0x800000E0
)

// tcgAlgorithms maps TPM_ALG_ID values to the banks the package replays.
var tcgAlgorithms = map[uint16]crypto.Hash{
	0x0004: crypto.SHA1,
	0x000B: crypto.SHA256,
	0x000C: crypto.SHA384,
	0x000D: crypto.SHA512,
}

var specIDSignature = []byte("Spec ID Event03\x00")

// Event is one TCG_PCR_EVENT2 record. Digests holds the banks the package
// knows; digests of other algorithms the header declares are skipped.
type Event struct {
	PCR     int
	Type    uint32
	Digests map[crypto.Hash][]byte
	Data    []byte
}

// logReader bounds-checks every read against the remaining input.
type logReader struct {
	raw []byte
	off int
}

func (r *logReader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.raw)-r.off {
		return nil, false
	}
	b := r.raw[r.off : r.off+n]
	r.off += n
	return b, true
}

func (r *logReader) u32() (uint32, bool) {
	b, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func (r *logReader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

// ParseEventLog reads a TCG2 crypto-agile event log and returns the
// TCG_PCR_EVENT2 records after its Spec ID Event03 header, in log order. It
// refuses a log it cannot read with a *MalformedEventLogError naming the
// failing record's first byte.
func ParseEventLog(raw []byte) ([]Event, error) {
	sizes, start, err := parseSpecID(raw)
	if err != nil {
		return nil, err
	}
	r := &logReader{raw: raw, off: start}
	var events []Event
	for r.off < len(raw) {
		at := r.off
		bad := func(reason string) error { return &MalformedEventLogError{Offset: at, Reason: reason} }
		pcr, ok1 := r.u32()
		typ, ok2 := r.u32()
		count, ok3 := r.u32()
		if !ok1 || !ok2 || !ok3 {
			return nil, bad("truncated record header")
		}
		e := Event{PCR: int(pcr), Type: typ, Digests: make(map[crypto.Hash][]byte)}
		for i := uint32(0); i < count; i++ {
			alg, ok := r.u16()
			if !ok {
				return nil, bad("truncated digest algorithm")
			}
			size, declared := sizes[alg]
			if !declared {
				return nil, bad(fmt.Sprintf("digest algorithm 0x%04x is not declared in the header", alg))
			}
			d, ok := r.take(size)
			if !ok {
				return nil, bad(fmt.Sprintf("truncated 0x%04x digest", alg))
			}
			if h, known := tcgAlgorithms[alg]; known {
				e.Digests[h] = bytes.Clone(d)
			}
		}
		size, ok := r.u32()
		if !ok {
			return nil, bad("truncated event size")
		}
		data, ok := r.take(int(size))
		if !ok || uint64(size) != uint64(len(data)) {
			return nil, bad(fmt.Sprintf("event size %d runs past the end of the log", size))
		}
		e.Data = bytes.Clone(data)
		events = append(events, e)
	}
	return events, nil
}

// parseSpecID reads the TCG_PCClientPCREvent header and its Spec ID Event03
// algorithm table, returning the declared digest size of each algorithm and
// the offset of the first TCG_PCR_EVENT2 record.
func parseSpecID(raw []byte) (map[uint16]int, int, error) {
	bad := func(reason string) error { return &MalformedEventLogError{Offset: 0, Reason: reason} }
	r := &logReader{raw: raw}
	_, ok1 := r.u32() // pcrIndex
	typ, ok2 := r.u32()
	_, ok3 := r.take(20) // SHA-1 digest
	size, ok4 := r.u32()
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, 0, bad("truncated header event")
	}
	if typ != EventNoAction {
		return nil, 0, bad(fmt.Sprintf("the first event is type 0x%x, not EV_NO_ACTION", typ))
	}
	body, ok := r.take(int(size))
	if !ok || uint64(size) != uint64(len(body)) {
		return nil, 0, bad("the header event runs past the end of the log")
	}
	s := &logReader{raw: body}
	sig, ok := s.take(len(specIDSignature))
	if !ok || !bytes.Equal(sig, specIDSignature) {
		return nil, 0, bad("the header is not Spec ID Event03")
	}
	_, ok1 = s.take(8) // platformClass, minor, major, errata, uintnSize
	n, ok2 := s.u32()
	if !ok1 || !ok2 {
		return nil, 0, bad("truncated Spec ID Event03")
	}
	sizes := make(map[uint16]int)
	for i := uint32(0); i < n; i++ {
		alg, ok1 := s.u16()
		dsize, ok2 := s.u16()
		if !ok1 || !ok2 {
			return nil, 0, bad("truncated algorithm table")
		}
		if h, known := tcgAlgorithms[alg]; known && int(dsize) != h.Size() {
			return nil, 0, bad(fmt.Sprintf("the header declares %v digests of %d bytes", h, dsize))
		}
		sizes[alg] = int(dsize)
	}
	vlen, ok := s.take(1)
	if !ok {
		return nil, 0, bad("truncated vendor info size")
	}
	if _, ok := s.take(int(vlen[0])); !ok {
		return nil, 0, bad("truncated vendor info")
	}
	return sizes, r.off, nil
}

// ReplayEventLog extends each PCR of bank h from its records in log order,
// as Replay does, skipping EV_NO_ACTION records (they extend nothing). A
// StartupLocality EV_NO_ACTION record seeds PCR 0 with its locality
// (0x00..0L) before the first extend, as TCG PC Client 10.4.5.3 specifies. A
// record without an h digest gives a *MissingBankError.
func ReplayEventLog(events []Event, h crypto.Hash) (map[int][]byte, error) {
	if err := checkHash(h); err != nil {
		return nil, err
	}
	pcrs := make(map[int][]byte)
	extends := make(map[int]int) // digests extended per PCR, for DigestSizeError.Index
	for _, e := range events {
		if e.Type == EventNoAction {
			// A StartupLocality record extends nothing, but the locality
			// the CRTM started at is PCR 0's initial value: 0x00..0L
			// (TCG PC Client 10.4.5.3). Other EV_NO_ACTION records are
			// skipped.
			if loc, ok := startupLocality(e); ok {
				if _, extended := pcrs[0]; !extended {
					seed := make([]byte, h.Size())
					seed[len(seed)-1] = loc
					pcrs[0] = seed
				}
			}
			continue
		}
		d, ok := e.Digests[h]
		if !ok {
			return nil, &MissingBankError{Hash: h}
		}
		if len(d) != h.Size() {
			return nil, &DigestSizeError{Hash: h, Index: extends[e.PCR], Got: len(d)}
		}
		extends[e.PCR]++
		pcr, ok := pcrs[e.PCR]
		if !ok {
			pcr = make([]byte, h.Size())
		}
		w := h.New()
		_, _ = w.Write(pcr) // hash.Hash.Write never returns an error
		_, _ = w.Write(d)
		pcrs[e.PCR] = w.Sum(nil)
	}
	return pcrs, nil
}

// startupLocalitySignature opens a TCG_EfiStartupLocalityEvent's data.
const startupLocalitySignature = "StartupLocality\x00"

// startupLocality is the locality an EV_NO_ACTION StartupLocality record on
// PCR 0 names, and whether e is such a record.
func startupLocality(e Event) (byte, bool) {
	if e.Type != EventNoAction || e.PCR != 0 || len(e.Data) != len(startupLocalitySignature)+1 ||
		string(e.Data[:len(startupLocalitySignature)]) != startupLocalitySignature {
		return 0, false
	}
	return e.Data[len(startupLocalitySignature)], true
}

// CheckEventLog parses raw, replays it for every bank and compares each PCR
// the bank predicts. It returns nil when every PCR matches, a
// *MissingBankError when the log lacks a bank, and otherwise the
// errors.Join of every *PCRMismatchError, in bank then PCR order.
func CheckEventLog(raw []byte, banks []Bank) error {
	events, err := ParseEventLog(raw)
	if err != nil {
		return err
	}
	var mismatches []error
	for _, bank := range banks {
		replayed, err := ReplayEventLog(events, bank.Hash)
		if err != nil {
			return err
		}
		pcrs := make([]int, 0, len(bank.PCRs))
		for pcr := range bank.PCRs {
			pcrs = append(pcrs, pcr)
		}
		sort.Ints(pcrs)
		for _, pcr := range pcrs {
			if got := replayed[pcr]; !bytes.Equal(got, bank.PCRs[pcr]) {
				mismatches = append(mismatches, &PCRMismatchError{
					Hash: bank.Hash, PCR: pcr, Predicted: bank.PCRs[pcr], Replayed: got,
				})
			}
		}
	}
	return errors.Join(mismatches...)
}
