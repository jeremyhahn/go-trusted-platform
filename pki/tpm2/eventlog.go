package tpm2

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

// EventType indicates what kind of data an event is reporting.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
type EventType uint32

var eventTypeStrings = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
}

type specIDEventHeader struct {
	Signature     [16]byte
	PlatformClass uint32
	VersionMinor  uint8
	VersionMajor  uint8
	Errata        uint8
	UintnSize     uint8
	NumAlgs       uint32
}

// EventLog is a parsed measurement log. This contains unverified data representing
// boot events that must be replayed against PCR values to determine authenticity.
type EventLog struct {
	// Algs holds the set of algorithms that the event log uses.
	Algs []HashAlg

	rawEvents   []rawEvent
	specIDEvent *specIDEvent
}

type rawEvent struct {
	sequence int
	index    int
	typ      EventType
	data     []byte
	digests  []digest
}

// EV_NO_ACTION is a special event type that indicates information to the parser
// instead of holding a measurement. For TPM 2.0, this event type is used to signal
// switching from SHA1 format to a variable length digest.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
const eventTypeNoAction = 0x03

// TPM 1.2 event log format. See "5.1 SHA1 Event Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

type eventSizeErr struct {
	eventSize uint32
	logSize   int
}

func (e *eventSizeErr) Error() string {
	return fmt.Sprintf("event data size (%d bytes) is greater than remaining measurement log (%d bytes)", e.eventSize, e.logSize)
}

type digest struct {
	hash crypto.Hash
	data []byte
}

type specIDEvent struct {
	algs []specAlgSize
}

type specAlgSize struct {
	ID   uint16
	Size uint16
}

const (
	wantMajor  = 2
	wantMinor  = 0
	wantErrata = 0
)

// TPM 2.0 event log format. See "5.2 Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

// Expected values for various Spec ID Event fields.
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=19
var wantSignature = [16]byte{0x53, 0x70,
	0x65, 0x63, 0x20, 0x49,
	0x44, 0x20, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x30,
	0x33, 0x00} // "Spec ID Event03\0"

// ParseEventLog parses an unverified measurement log.
func ParseEventLog(measurementLog []byte) (*EventLog, error) {
	var specID *specIDEvent
	r := bytes.NewBuffer(measurementLog)
	parseFn := parseRawEvent
	var el EventLog
	e, err := parseFn(r, specID)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	if e.typ == eventTypeNoAction && len(e.data) >= binary.Size(specIDEventHeader{}) {
		specID, err = parseSpecIDEvent(e.data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spec ID event: %v", err)
		}
		for _, alg := range specID.algs {
			switch tpm2.TPMAlgID(alg.ID) {
			case tpm2.TPMAlgSHA1:
				el.Algs = append(el.Algs, HashSHA1)
			case tpm2.TPMAlgSHA256:
				el.Algs = append(el.Algs, HashSHA256)
			}
		}
		if len(el.Algs) == 0 {
			return nil, fmt.Errorf("measurement log didn't use sha1 or sha256 digests")
		}
		// Switch to parsing crypto agile events. Don't include this in the
		// replayed events since it intentionally doesn't extend the PCRs.
		//
		// Note that this doesn't actually guarantee that events have SHA256
		// digests.
		parseFn = parseRawEvent2
		el.specIDEvent = specID
	} else {
		el.Algs = []HashAlg{HashSHA1}
		el.rawEvents = append(el.rawEvents, e)
	}
	sequence := 1
	for r.Len() != 0 {
		e, err := parseFn(r, specID)
		if err != nil {
			return nil, err
		}
		e.sequence = sequence
		sequence++
		el.rawEvents = append(el.rawEvents, e)
	}
	return &el, nil
}

// parseSpecIDEvent parses a TCG_EfiSpecIDEventStruct structure from the reader.
//
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
func parseSpecIDEvent(b []byte) (*specIDEvent, error) {
	r := bytes.NewReader(b)
	var header specIDEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading event header: %w: %X", err, b)
	}
	if header.Signature != wantSignature {
		return nil, fmt.Errorf("invalid spec id signature: %x", header.Signature)
	}
	if header.VersionMajor != wantMajor {
		return nil, fmt.Errorf("invalid spec major version, got %02x, wanted %02x",
			header.VersionMajor, wantMajor)
	}
	if header.VersionMinor != wantMinor {
		return nil, fmt.Errorf("invalid spec minor version, got %02x, wanted %02x",
			header.VersionMajor, wantMinor)
	}

	// TODO(ericchiang): Check errata? Or do we expect that to change in ways
	// we're okay with?

	specAlg := specAlgSize{}
	e := specIDEvent{}
	for i := 0; i < int(header.NumAlgs); i++ {
		if err := binary.Read(r, binary.LittleEndian, &specAlg); err != nil {
			return nil, fmt.Errorf("reading algorithm: %v", err)
		}
		e.algs = append(e.algs, specAlg)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, fmt.Errorf("reading vender info size: %v", err)
	}
	if r.Len() != int(vendorInfoSize) {
		return nil, fmt.Errorf("reading vendor info, expected %d remaining bytes, got %d", vendorInfoSize, r.Len())
	}
	return &e, nil
}

func parseRawEvent(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEventHeader
	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, fmt.Errorf("header deserialization error: %w", err)
	}
	if h.EventSize > uint32(r.Len()) {
		return event, &eventSizeErr{h.EventSize, r.Len()}
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, fmt.Errorf("reading data error: %w", err)
	}

	digests := []digest{{hash: crypto.SHA1, data: h.Digest[:]}}

	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: digests,
	}, nil
}

func parseRawEvent2(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEvent2Header

	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	event.typ = EventType(h.Type)
	event.index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if r.Len() < int(alg.Size) {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.data = make([]byte, alg.Size)
			digest.hash = HashAlg(alg.ID).cryptoHash()
		}
		if len(digest.data) == 0 {
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.data); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err = binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize > uint32(r.Len()) {
		return event, &eventSizeErr{eventSize, r.Len()}
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, err
}
