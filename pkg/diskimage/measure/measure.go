// Package measure predicts the PCR values a factory image determines, from
// the bytes the build writes to the card, for the measurement manifest
// (docs/factory-image/architecture.md §8).
//
// The values are predicted, not measured: each predictor replays the event
// sequence the boot chain extends into one PCR (U-Boot's EFI TCG2 protocol,
// then the Linux EFI stub) over the build's own inputs. Which PCRs the
// manifest carries, and the exact event sequences, are settled by replaying
// a live event log on the QEMU virt stand-in (docs/plans/669.md slice 5).
package measure

import (
	"crypto"
	_ "crypto/sha1"   // registers SHA-1 for crypto.Hash.Available
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.Available
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.Available
	"encoding/binary"
	"unicode/utf16"
)

// GUID is an EFI_GUID in its wire encoding: the first three fields little
// endian, the last eight bytes as written.
type GUID [16]byte

// NewGUID builds the wire encoding of the GUID a-b-c-d.
func NewGUID(a uint32, b, c uint16, d [8]byte) GUID {
	var g GUID
	binary.LittleEndian.PutUint32(g[0:4], a)
	binary.LittleEndian.PutUint16(g[4:6], b)
	binary.LittleEndian.PutUint16(g[6:8], c)
	copy(g[8:], d[:])
	return g
}

var (
	// EFIGlobalVariable is EFI_GLOBAL_VARIABLE, the vendor of SecureBoot, PK and KEK.
	EFIGlobalVariable = NewGUID(0x8be4df61, 0x93ca, 0x11d2, [8]byte{0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c})
	// EFIImageSecurityDatabase is EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor of db and dbx.
	EFIImageSecurityDatabase = NewGUID(0xd719b2cb, 0x3d3a, 0x4596, [8]byte{0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f})
)

// The EV_EFI_ACTION strings U-Boot measures (TCG PC Client PFP §10.4.4).
const (
	ActionCallingEFIApplication = "Calling EFI Application from Boot Option"
	ActionExitBootServices      = "Exit Boot Services Invocation"
	ActionExitBootServicesOK    = "Exit Boot Services Returned with Success"
)

// separatorData is the EV_SEPARATOR event data of a successful boot.
var separatorData = []byte{0, 0, 0, 0}

func checkHash(h crypto.Hash) error {
	if !h.Available() {
		return &UnsupportedBankError{Hash: h}
	}
	return nil
}

// Digest is h over data: the digest an event extends.
func Digest(h crypto.Hash, data []byte) ([]byte, error) {
	if err := checkHash(h); err != nil {
		return nil, err
	}
	w := h.New()
	_, _ = w.Write(data) // hash.Hash.Write never returns an error
	return w.Sum(nil), nil
}

// SeparatorDigest is the digest of an EV_SEPARATOR event.
func SeparatorDigest(h crypto.Hash) ([]byte, error) { return Digest(h, separatorData) }

// ActionDigest is the digest of an EV_EFI_ACTION event with the given string.
func ActionDigest(h crypto.Hash, action string) ([]byte, error) {
	return Digest(h, []byte(action))
}

// VariableData is the UEFI_VARIABLE_DATA structure that a variable event
// (EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_AUTHORITY) hashes: the
// vendor GUID, the name's length in UTF-16 code units, the data's length,
// the name in UTF-16LE without its terminator, then the data.
func VariableData(vendor GUID, name string, data []byte) []byte {
	units := utf16.Encode([]rune(name))
	out := make([]byte, 0, 32+2*len(units)+len(data))
	out = append(out, vendor[:]...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(units)))
	out = binary.LittleEndian.AppendUint64(out, uint64(len(data)))
	for _, u := range units {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return append(out, data...)
}

// SignatureData is the EFI_SIGNATURE_DATA of one db entry: the owner GUID,
// then the signature (an X.509 certificate's DER for an EFI_CERT_X509 list).
func SignatureData(owner GUID, signature []byte) []byte {
	out := make([]byte, 0, len(owner)+len(signature))
	out = append(out, owner[:]...)
	return append(out, signature...)
}

// Replay extends a PCR that starts at zero with each digest in order and
// returns its final value.
func Replay(h crypto.Hash, digests ...[]byte) ([]byte, error) {
	if err := checkHash(h); err != nil {
		return nil, err
	}
	pcr := make([]byte, h.Size())
	for i, d := range digests {
		if len(d) != h.Size() {
			return nil, &DigestSizeError{Hash: h, Index: i, Got: len(d)}
		}
		w := h.New()
		_, _ = w.Write(pcr)
		_, _ = w.Write(d)
		pcr = w.Sum(nil)
	}
	return pcr, nil
}

// replayEvents hashes each event's data and replays the digests.
func replayEvents(h crypto.Hash, events ...[]byte) ([]byte, error) {
	if err := checkHash(h); err != nil {
		return nil, err
	}
	digests := make([][]byte, len(events))
	for i, e := range events {
		digests[i], _ = Digest(h, e)
	}
	return Replay(h, digests...)
}

// SecureBootVariables are the authenticated variables U-Boot preseeds, each
// the EFI_SIGNATURE_LIST bytes the build compiles into it. DBX may be empty.
type SecureBootVariables struct {
	PK, KEK, DB, DBX []byte
}

// PredictPCR7 replays PCR 7 under U-Boot's Secure Boot: SecureBoot (1), PK,
// KEK, db and dbx as EV_EFI_VARIABLE_DRIVER_CONFIG, the separator, then one
// EV_EFI_VARIABLE_AUTHORITY per distinct db entry that verified an image,
// in the order first used. Each authority is a SignatureData. An image
// without PK, KEK or db does not boot with Secure Boot, so it is refused.
func PredictPCR7(h crypto.Hash, v SecureBootVariables, authorities ...[]byte) ([]byte, error) {
	for _, in := range []struct {
		name string
		data []byte
	}{{"PK", v.PK}, {"KEK", v.KEK}, {"db", v.DB}} {
		if len(in.data) == 0 {
			return nil, &MissingInputError{PCR: 7, Input: in.name}
		}
	}
	events := [][]byte{
		VariableData(EFIGlobalVariable, "SecureBoot", []byte{1}),
		VariableData(EFIGlobalVariable, "PK", v.PK),
		VariableData(EFIGlobalVariable, "KEK", v.KEK),
		VariableData(EFIImageSecurityDatabase, "db", v.DB),
		VariableData(EFIImageSecurityDatabase, "dbx", v.DBX),
		separatorData,
	}
	for _, a := range authorities {
		if len(a) == 0 {
			return nil, &MissingInputError{PCR: 7, Input: "authority"}
		}
		events = append(events, VariableData(EFIImageSecurityDatabase, "db", a))
	}
	return replayEvents(h, events...)
}

// PredictPCR5 replays PCR 5 on MBR boot media, where U-Boot measures no
// partition table: the separator, then the two ExitBootServices actions.
func PredictPCR5(h crypto.Hash) ([]byte, error) {
	return replayEvents(h, separatorData,
		[]byte(ActionExitBootServices), []byte(ActionExitBootServicesOK))
}

// PredictPCR9 replays PCR 9 as the Linux EFI stub extends it: the load
// options the stub received (none when loadOptions is nil), then the
// initrd. The initrd is required.
func PredictPCR9(h crypto.Hash, loadOptions, initrd []byte) ([]byte, error) {
	if len(initrd) == 0 {
		return nil, &MissingInputError{PCR: 9, Input: "initrd"}
	}
	var events [][]byte
	if loadOptions != nil {
		events = append(events, loadOptions)
	}
	return replayEvents(h, append(events, initrd)...)
}
