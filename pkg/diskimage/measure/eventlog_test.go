package measure

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"testing"
)

// logAlg is one row of the Spec ID Event03 algorithm table the test encoder
// writes. hash is the bank an event's digest is taken from; zero means an
// algorithm the parser does not know, written as junk of the declared size.
type logAlg struct {
	id   uint16
	size uint16
	hash crypto.Hash
}

// logEvent is one TCG_PCR_EVENT2 record the test encoder writes.
type logEvent struct {
	pcr    int
	typ    uint32
	digest map[crypto.Hash][]byte
	data   []byte
}

var testAlgIDs = map[crypto.Hash]uint16{
	crypto.SHA1: 0x0004, crypto.SHA256: 0x000B, crypto.SHA384: 0x000C, crypto.SHA512: 0x000D,
}

func algsFor(banks []crypto.Hash) []logAlg {
	algs := make([]logAlg, 0, len(banks))
	for _, h := range banks {
		algs = append(algs, logAlg{id: testAlgIDs[h], size: uint16(h.Size()), hash: h})
	}
	return algs
}

// encodeEventLog writes a TCG2 crypto-agile event log, little endian, by
// hand from the TCG PC Client PFP layouts: the TCG_PCClientPCREvent header
// carrying Spec ID Event03, then one TCG_PCR_EVENT2 per event.
func encodeEventLog(banks []crypto.Hash, events ...logEvent) []byte {
	return encodeEventLogAlgs(algsFor(banks), events...)
}

func encodeEventLogAlgs(algs []logAlg, events ...logEvent) []byte {
	le := binary.LittleEndian
	var spec []byte
	spec = append(spec, "Spec ID Event03\x00"...)
	spec = le.AppendUint32(spec, 0) // platformClass
	spec = append(spec, 0, 2, 0, 2) // minor, major, errata, uintnSize
	spec = le.AppendUint32(spec, uint32(len(algs)))
	for _, a := range algs {
		spec = le.AppendUint16(spec, a.id)
		spec = le.AppendUint16(spec, a.size)
	}
	spec = append(spec, 0) // vendorInfoSize

	var out []byte
	out = le.AppendUint32(out, 0)                     // pcrIndex
	out = le.AppendUint32(out, uint32(EventNoAction)) // eventType
	out = append(out, make([]byte, 20)...)            // SHA-1 digest
	out = le.AppendUint32(out, uint32(len(spec)))
	out = append(out, spec...)

	for _, e := range events {
		out = le.AppendUint32(out, uint32(e.pcr))
		out = le.AppendUint32(out, e.typ)
		out = le.AppendUint32(out, uint32(len(algs)))
		for _, a := range algs {
			out = le.AppendUint16(out, a.id)
			d := e.digest[a.hash]
			if a.hash == 0 || d == nil {
				d = bytes.Repeat([]byte{0xee}, int(a.size))
			}
			out = append(out, d...)
		}
		out = le.AppendUint32(out, uint32(len(e.data)))
		out = append(out, e.data...)
	}
	return out
}

// dataEvent is an event whose digest in every bank is the digest of its data.
func dataEvent(t *testing.T, banks []crypto.Hash, pcr int, typ uint32, data []byte) logEvent {
	t.Helper()
	e := logEvent{pcr: pcr, typ: typ, digest: map[crypto.Hash][]byte{}, data: data}
	for _, h := range banks {
		d, err := Digest(h, data)
		if err != nil {
			t.Fatal(err)
		}
		e.digest[h] = d
	}
	return e
}

// startupLocalityEvent is the EV_NO_ACTION TCG_EfiStartupLocalityEvent
// firmware logs when the H-CRTM or S-CRTM started at locality loc.
func startupLocalityEvent(banks []crypto.Hash, loc byte) logEvent {
	e := logEvent{pcr: 0, typ: EventNoAction, digest: map[crypto.Hash][]byte{}, data: append([]byte("StartupLocality\x00"), loc)}
	for _, h := range banks {
		e.digest[h] = make([]byte, h.Size())
	}
	return e
}

// imageEvents is the boot chain's event sequence for img, written event by
// event as firmware, shim-less systemd-stub and the kernel log it. It uses
// the event encodings only, never the PCR predictors.
func imageEvents(t *testing.T, img Image, banks ...crypto.Hash) []logEvent {
	t.Helper()
	kernel, err := UKIKernel(img.UKI)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := ukiSections(img.UKI)
	if err != nil {
		t.Fatal(err)
	}
	pe := func(pcr int, image []byte) logEvent {
		e := logEvent{pcr: pcr, typ: EventEFIBootServicesApplication, digest: map[crypto.Hash][]byte{}}
		for _, h := range banks {
			d, err := AuthenticodeDigest(h, image)
			if err != nil {
				t.Fatal(err)
			}
			e.digest[h] = d
		}
		return e
	}
	sep := []byte{0, 0, 0, 0}
	gv, sdb := EFIGlobalVariable, EFIImageSecurityDatabase
	// Firmware logs its startup locality first (TCG PC Client section 10.4.5, item 3);
	// an EV_NO_ACTION record extends nothing, so its digests are zero.
	locality := startupLocalityEvent(banks, 0)
	// Any other EV_NO_ACTION record is skipped whatever its digests hold.
	junk := logEvent{pcr: 0, typ: EventNoAction, digest: map[crypto.Hash][]byte{}, data: []byte("SP800-155 Event\x00")}
	for _, h := range banks {
		junk.digest[h] = bytes.Repeat([]byte{0x5a}, h.Size())
	}
	return []logEvent{
		locality,
		dataEvent(t, banks, 0, EventSCRTMVersion, []byte(testUBootVersion+"\x00")),
		junk,
		dataEvent(t, banks, 0, EventSeparator, sep),
		pe(4, img.UKI),
		dataEvent(t, banks, 4, EventEFIAction, []byte(ActionCallingEFIApplication)),
		dataEvent(t, banks, 4, EventSeparator, sep),
		pe(4, kernel),
		dataEvent(t, banks, 7, EventEFIVariableDriverConfig, VariableData(gv, "SecureBoot", []byte{1})),
		dataEvent(t, banks, 7, EventEFIVariableDriverConfig, VariableData(gv, "PK", img.SecureBoot.PK)),
		dataEvent(t, banks, 7, EventEFIVariableDriverConfig, VariableData(gv, "KEK", img.SecureBoot.KEK)),
		dataEvent(t, banks, 7, EventEFIVariableDriverConfig, VariableData(sdb, "db", img.SecureBoot.DB)),
		dataEvent(t, banks, 7, EventEFIVariableDriverConfig, VariableData(sdb, "dbx", img.SecureBoot.DBX)),
		dataEvent(t, banks, 7, EventSeparator, sep),
		dataEvent(t, banks, 7, EventEFIVariableAuthority, VariableData(sdb, "db", img.Authority)),
		dataEvent(t, banks, 9, EventTag, StubLoadOptions(sections[".cmdline"])),
		dataEvent(t, banks, 9, EventTag, sections[".initrd"]),
	}
}

func imageLog(t *testing.T, img Image, banks ...crypto.Hash) []byte {
	t.Helper()
	return encodeEventLog(banks, imageEvents(t, img, banks...)...)
}

func lastEvent(events []logEvent, pcr int) int {
	at := -1
	for i, e := range events {
		if e.pcr == pcr {
			at = i
		}
	}
	return at
}

func TestParseEventLogReadsTheSpecIDHeader(t *testing.T) {
	banks := []crypto.Hash{crypto.SHA256, crypto.SHA384}
	want := []logEvent{
		dataEvent(t, banks, 0, EventSCRTMVersion, []byte("v1\x00")),
		dataEvent(t, banks, 7, EventSeparator, []byte{0, 0, 0, 0}),
		dataEvent(t, banks, 9, EventTag, nil),
	}
	plain := encodeEventLog(banks, want...)
	unknown := encodeEventLogAlgs(append(algsFor(banks[:1]), logAlg{id: 0x0012, size: 32}, algsFor(banks[1:])[0]), want...)
	for name, raw := range map[string][]byte{"sha256+sha384": plain, "with an unknown algorithm": unknown} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseEventLog(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatalf("%d events, want %d", len(got), len(want))
			}
			for i, w := range want {
				g := got[i]
				if g.PCR != w.pcr || g.Type != w.typ || !bytes.Equal(g.Data, w.data) || len(g.Digests) != len(banks) {
					t.Fatalf("event %d: %+v, want %+v", i, g, w)
				}
				for _, h := range banks {
					if !bytes.Equal(g.Digests[h], w.digest[h]) {
						t.Fatalf("event %d %v digest %x, want %x", i, h, g.Digests[h], w.digest[h])
					}
				}
			}
		})
	}
}

func TestParseEventLogRefusesMalformedLogs(t *testing.T) {
	banks := []crypto.Hash{crypto.SHA256}
	header := len(encodeEventLog(banks))
	one := func() []byte {
		return encodeEventLog(banks, dataEvent(t, banks, 4, EventTag, []byte("abc")))
	}
	for _, tc := range []struct {
		name   string
		raw    func() []byte
		offset int
	}{
		{"empty", func() []byte { return nil }, 0},
		{"not Spec ID Event03", func() []byte { raw := one(); raw[32] = 'X'; return raw }, 0},
		{"first event not EV_NO_ACTION", func() []byte { raw := one(); raw[4] = 1; return raw }, 0},
		{"truncated in the digests", func() []byte { return one()[:header+12+2+5] }, header},
		{"eventSize past the end", func() []byte { raw := one(); return raw[:len(raw)-1] }, header},
		{"undeclared algorithm", func() []byte {
			raw := one()
			binary.LittleEndian.PutUint16(raw[header+12:], 0x000D)
			return raw
		}, header},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEventLog(tc.raw())
			var me *MalformedEventLogError
			if !errors.As(err, &me) || me.Offset != tc.offset {
				t.Fatalf("err %v, want a MalformedEventLogError at byte %d", err, tc.offset)
			}
			if me.Error() == "" || me.Reason == "" {
				t.Fatalf("empty message: %+v", me)
			}
		})
	}
}

func TestReplayEventLogSkipsNoAction(t *testing.T) {
	img, _ := testImage()
	events, err := ParseEventLog(imageLog(t, img, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	pcrs, err := ReplayEventLog(events, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	version, _ := Digest(crypto.SHA256, []byte(testUBootVersion+"\x00"))
	separator, _ := SeparatorDigest(crypto.SHA256)
	want, _ := Replay(crypto.SHA256, version, separator)
	if !bytes.Equal(pcrs[0], want) {
		t.Fatalf("PCR 0 replays to %x, want %x", pcrs[0], want)
	}

	var mb *MissingBankError
	if _, err := ReplayEventLog(events, crypto.SHA384); !errors.As(err, &mb) || mb.Hash != crypto.SHA384 {
		t.Fatalf("a bank the log lacks: err %v, want a MissingBankError", err)
	}
	if mb.Error() == "" {
		t.Fatal("MissingBankError has an empty message")
	}
}

// TestReplayEventLogSeedsPCR0FromTheStartupLocality covers a log whose
// StartupLocality record names locality 3: PCR 0 starts at 0x00..03, not
// zero, before the first digest extends it (TCG PC Client section 10.4.5, item 3).
func TestReplayEventLogSeedsPCR0FromTheStartupLocality(t *testing.T) {
	img, _ := testImage()
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384}
	events := imageEvents(t, img, hashes...)
	events[0] = startupLocalityEvent(hashes, 3)
	parsed, err := ParseEventLog(encodeEventLog(hashes, events...))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hashes {
		pcrs, err := ReplayEventLog(parsed, h)
		if err != nil {
			t.Fatal(err)
		}
		version, _ := Digest(h, []byte(testUBootVersion+"\x00"))
		separator, _ := SeparatorDigest(h)
		want := make([]byte, h.Size())
		want[len(want)-1] = 3
		for _, d := range [][]byte{version, separator} {
			w := h.New()
			w.Write(want)
			w.Write(d)
			want = w.Sum(nil)
		}
		if !bytes.Equal(pcrs[0], want) {
			t.Fatalf("%v: PCR 0 replays to %x, want %x from locality 3", h, pcrs[0], want)
		}
		zero, _ := Replay(h, version, separator)
		if bytes.Equal(pcrs[0], zero) {
			t.Fatalf("%v: PCR 0 replayed from zero despite locality 3", h)
		}
	}

	// A locality-3 log no longer matches a prediction made for locality 0.
	banks, err := Predict(img, hashes...)
	if err != nil {
		t.Fatal(err)
	}
	var pm *PCRMismatchError
	if err := CheckEventLog(encodeEventLog(hashes, events...), banks); !errors.As(err, &pm) || pm.PCR != 0 {
		t.Fatalf("locality 3 against a locality-0 prediction: err %v, want a PCR 0 mismatch", err)
	}
}

func TestCheckEventLogMatchesThePrediction(t *testing.T) {
	img, _ := testImage()
	banks, err := Predict(img, crypto.SHA256, crypto.SHA384)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckEventLog(imageLog(t, img, crypto.SHA256, crypto.SHA384), banks); err != nil {
		t.Fatal(err)
	}
}

func TestCheckEventLogReportsEveryMismatch(t *testing.T) {
	img, _ := testImage()
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384}
	banks, err := Predict(img, hashes...)
	if err != nil {
		t.Fatal(err)
	}

	events := imageEvents(t, img, hashes...)
	events[lastEvent(events, 9)].digest[crypto.SHA256][0] ^= 1
	events[lastEvent(events, 4)].digest[crypto.SHA256][0] ^= 1
	err = CheckEventLog(encodeEventLog(hashes, events...), banks)
	var pm *PCRMismatchError
	if !errors.As(err, &pm) {
		t.Fatalf("err %v, want a PCRMismatchError", err)
	}
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("err %T does not join its mismatches", err)
	}
	var got []int
	for _, e := range joined.Unwrap() {
		if !errors.As(e, &pm) {
			t.Fatalf("%v is not a PCRMismatchError", e)
		}
		if pm.Hash != crypto.SHA256 || pm.Predicted == nil || pm.Replayed == nil || bytes.Equal(pm.Predicted, pm.Replayed) {
			t.Fatalf("mismatch %+v", pm)
		}
		if !bytes.Equal(pm.Predicted, banks[0].PCRs[pm.PCR]) {
			t.Fatalf("PCR %d predicted %x, want the manifest's %x", pm.PCR, pm.Predicted, banks[0].PCRs[pm.PCR])
		}
		if pm.Error() == "" {
			t.Fatal("PCRMismatchError has an empty message")
		}
		got = append(got, pm.PCR)
	}
	if len(got) != 2 || got[0] != 4 || got[1] != 9 {
		t.Fatalf("mismatched PCRs %v, want [4 9]", got)
	}

	var no7 []logEvent
	for _, e := range imageEvents(t, img, hashes...) {
		if e.pcr != 7 {
			no7 = append(no7, e)
		}
	}
	err = CheckEventLog(encodeEventLog(hashes, no7...), banks)
	if !errors.As(err, &pm) || pm.PCR != 7 || pm.Replayed != nil {
		t.Fatalf("no PCR 7 events: err %v, want a PCR 7 mismatch with nothing replayed", err)
	}

	var mb *MissingBankError
	err = CheckEventLog(imageLog(t, img, crypto.SHA256), banks)
	if !errors.As(err, &mb) || mb.Hash != crypto.SHA384 {
		t.Fatalf("no sha384 bank: err %v, want a MissingBankError for SHA-384", err)
	}
}
