package measure

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// The CBOR tags of draft-ietf-rats-corim-11 a measurement manifest uses.
const (
	TagUnsignedCoRIM = 501 // tagged-unsigned-corim-map
	TagCoMID         = 506 // tagged-concise-mid-tag
)

// ManifestVendor is the class-map vendor of every measurement manifest.
const ManifestVendor = "go-trusted-platform"

// manifestNamespace is the RFC 9562 namespace a manifest's tag identity is
// derived in. It is fixed: changing it changes every image's tag identity.
var manifestNamespace = uuid.MustParse("38fbcc14-c01c-416f-9a07-a59409341f48")

// namedInformation maps a bank's hash to its IANA Named Information Hash
// Algorithm Registry identifier, the alg of a CoRIM digest.
var namedInformation = map[crypto.Hash]int64{
	crypto.SHA256:   1,
	crypto.SHA384:   7,
	crypto.SHA512:   8,
	crypto.SHA3_256: 10,
	crypto.SHA3_384: 11,
	crypto.SHA3_512: 12,
}

// Manifest is what a measurement manifest says: the PCR values of one image
// for every predicted bank. It is the payload a signed CoRIM carries.
type Manifest struct {
	// TagID is the CoMID's tag identity and the CoRIM's id: ManifestTagID
	// of the image. An upgrade is a new image, so it has a new TagID.
	TagID uuid.UUID
	// Model is the environment's class-map model, "<target>/<model>",
	// for example "rpi/rpi4" or "qemu-virt/virt".
	Model string
	// Banks holds ManifestPCRs in every bank, one bank per hash.
	Banks []Bank
}

// ManifestTagID is the tag identity of the image whose SHA-256 is
// imageSHA256: an RFC 9562 version 8 name-based UUID, SHA-256 over
// manifestNamespace and the digest. The same image always gets the same tag.
func ManifestTagID(imageSHA256 []byte) (uuid.UUID, error) {
	if len(imageSHA256) != sha256.Size {
		return uuid.Nil, &InvalidManifestError{Reason: fmt.Sprintf("the image digest is %d bytes, not a SHA-256", len(imageSHA256))}
	}
	return uuid.NewHash(sha256.New(), manifestNamespace, imageSHA256, 8), nil
}

// InvalidManifestError reports a manifest that cannot be encoded, or bytes
// that are not a measurement manifest.
type InvalidManifestError struct {
	Reason string
	Err    error
}

func (e *InvalidManifestError) Error() string {
	if e.Err != nil {
		return "measure: invalid measurement manifest: " + e.Reason + ": " + e.Err.Error()
	}
	return "measure: invalid measurement manifest: " + e.Reason
}

// Unwrap returns the underlying error.
func (e *InvalidManifestError) Unwrap() error { return e.Err }

// The CoRIM structures a manifest encodes to, keyed as the CDDL keys them.
type (
	corimMap struct {
		ID   []byte     `cbor:"0,keyasint"`
		Tags []cbor.Tag `cbor:"1,keyasint"`
	}
	corimMapIn struct {
		ID   []byte        `cbor:"0,keyasint"`
		Tags []cbor.RawTag `cbor:"1,keyasint"`
	}
	comid struct {
		TagIdentity tagIdentity `cbor:"1,keyasint"`
		Triples     triples     `cbor:"4,keyasint"`
	}
	tagIdentity struct {
		TagID []byte `cbor:"0,keyasint"`
	}
	triples struct {
		Reference []referenceTriple `cbor:"0,keyasint,omitempty"`
	}
	referenceTriple struct {
		_      struct{} `cbor:",toarray"`
		Env    environment
		Claims []measurement
	}
	environment struct {
		Class classMap `cbor:"0,keyasint"`
	}
	classMap struct {
		Vendor string `cbor:"1,keyasint,omitempty"`
		Model  string `cbor:"2,keyasint,omitempty"`
	}
	measurement struct {
		Key *uint64       `cbor:"0,keyasint,omitempty"`
		Val measuredValue `cbor:"1,keyasint"`
	}
	measuredValue struct {
		Digests []digest `cbor:"2,keyasint,omitempty"`
	}
	digest struct {
		_   struct{} `cbor:",toarray"`
		Alg int64
		Val []byte
	}
)

var (
	encMode = func() cbor.EncMode {
		m, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
	decMode = func() cbor.DecMode {
		m, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
		if err != nil {
			panic(err)
		}
		return m
	}()
)

// validate checks that m holds a whole manifest: a tag identity, a model
// and ManifestPCRs, and nothing else, in every bank.
func (m Manifest) validate() error {
	if m.TagID == uuid.Nil {
		return &InvalidManifestError{Reason: "no tag identity"}
	}
	if m.Model == "" {
		return &InvalidManifestError{Reason: "no model"}
	}
	if len(m.Banks) == 0 {
		return &InvalidManifestError{Reason: "no PCR bank"}
	}
	seen := map[crypto.Hash]bool{}
	for _, b := range m.Banks {
		if _, ok := namedInformation[b.Hash]; !ok {
			return &UnsupportedBankError{Hash: b.Hash}
		}
		if seen[b.Hash] {
			return &InvalidManifestError{Reason: fmt.Sprintf("the %v bank appears twice", b.Hash)}
		}
		seen[b.Hash] = true
		for _, pcr := range ManifestPCRs {
			v, ok := b.PCRs[pcr]
			if !ok {
				return &InvalidManifestError{Reason: fmt.Sprintf("the %v bank has no PCR %d", b.Hash, pcr)}
			}
			if len(v) != b.Hash.Size() {
				return &InvalidManifestError{Reason: fmt.Sprintf("PCR %d is %d bytes, the %v bank needs %d", pcr, len(v), b.Hash, b.Hash.Size())}
			}
		}
		for pcr := range b.PCRs {
			if !slices.Contains(ManifestPCRs, pcr) {
				return &InvalidManifestError{Reason: fmt.Sprintf("the %v bank has PCR %d, which the image does not determine", b.Hash, pcr)}
			}
		}
	}
	return nil
}

// EncodeManifest encodes m as a tagged-unsigned-corim-map holding one CoMID:
// one reference triple whose environment is vendor ManifestVendor and model
// m.Model, and one measurement per PCR of ManifestPCRs, keyed by the PCR
// index, with one digest per bank. The encoding is deterministic (RFC 8949
// §4.2.1), so the same manifest always encodes to the same bytes. An
// incomplete manifest is refused.
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	claims := make([]measurement, 0, len(ManifestPCRs))
	for _, pcr := range ManifestPCRs {
		key := uint64(pcr)
		var digests []digest
		for _, b := range m.Banks {
			digests = append(digests, digest{Alg: namedInformation[b.Hash], Val: b.PCRs[pcr]})
		}
		claims = append(claims, measurement{Key: &key, Val: measuredValue{Digests: digests}})
	}
	id := m.TagID[:]
	tag, err := encMode.Marshal(comid{
		TagIdentity: tagIdentity{TagID: id},
		Triples: triples{Reference: []referenceTriple{{
			Env:    environment{Class: classMap{Vendor: ManifestVendor, Model: m.Model}},
			Claims: claims,
		}}},
	})
	if err != nil {
		return nil, &InvalidManifestError{Reason: "encoding the CoMID", Err: err}
	}
	out, err := encMode.Marshal(cbor.Tag{Number: TagUnsignedCoRIM, Content: corimMap{
		ID:   id,
		Tags: []cbor.Tag{{Number: TagCoMID, Content: tag}},
	}})
	if err != nil {
		return nil, &InvalidManifestError{Reason: "encoding the CoRIM", Err: err}
	}
	return out, nil
}

// DecodeManifest decodes what EncodeManifest encodes. It refuses anything
// else: another tag, more than one CoMID or reference triple, another
// vendor, a measurement without a PCR key, a digest in an unknown algorithm,
// or a manifest that validate refuses.
func DecodeManifest(data []byte) (Manifest, error) {
	var outer cbor.RawTag
	if err := decMode.Unmarshal(data, &outer); err != nil {
		return Manifest{}, &InvalidManifestError{Reason: "not a tagged CoRIM", Err: err}
	}
	if outer.Number != TagUnsignedCoRIM {
		return Manifest{}, &InvalidManifestError{Reason: fmt.Sprintf("CBOR tag %d, not an unsigned CoRIM (%d)", outer.Number, TagUnsignedCoRIM)}
	}
	var cm corimMapIn
	if err := decMode.Unmarshal(outer.Content, &cm); err != nil {
		return Manifest{}, &InvalidManifestError{Reason: "decoding the CoRIM", Err: err}
	}
	if len(cm.Tags) != 1 || cm.Tags[0].Number != TagCoMID {
		return Manifest{}, &InvalidManifestError{Reason: "the CoRIM does not hold exactly one CoMID"}
	}
	var raw []byte
	if err := decMode.Unmarshal(cm.Tags[0].Content, &raw); err != nil {
		return Manifest{}, &InvalidManifestError{Reason: "the CoMID is not a byte string", Err: err}
	}
	var c comid
	if err := decMode.Unmarshal(raw, &c); err != nil {
		return Manifest{}, &InvalidManifestError{Reason: "decoding the CoMID", Err: err}
	}
	id, err := uuid.FromBytes(c.TagIdentity.TagID)
	if err != nil {
		return Manifest{}, &InvalidManifestError{Reason: "the tag identity is not a UUID", Err: err}
	}
	if string(cm.ID) != string(c.TagIdentity.TagID) {
		return Manifest{}, &InvalidManifestError{Reason: "the CoRIM id is not the CoMID's tag identity"}
	}
	if len(c.Triples.Reference) != 1 {
		return Manifest{}, &InvalidManifestError{Reason: "the CoMID does not hold exactly one reference triple"}
	}
	ref := c.Triples.Reference[0]
	if ref.Env.Class.Vendor != ManifestVendor {
		return Manifest{}, &InvalidManifestError{Reason: fmt.Sprintf("vendor %q, not %q", ref.Env.Class.Vendor, ManifestVendor)}
	}
	m := Manifest{TagID: id, Model: ref.Env.Class.Model}
	index := map[crypto.Hash]int{}
	for _, claim := range ref.Claims {
		if claim.Key == nil {
			return Manifest{}, &InvalidManifestError{Reason: "a measurement has no PCR index"}
		}
		pcr := int(*claim.Key)
		if uint64(pcr) != *claim.Key || pcr < 0 {
			return Manifest{}, &InvalidManifestError{Reason: fmt.Sprintf("PCR index %d is out of range", *claim.Key)}
		}
		for _, d := range claim.Val.Digests {
			h, err := hashOf(d.Alg)
			if err != nil {
				return Manifest{}, err
			}
			i, ok := index[h]
			if !ok {
				i = len(m.Banks)
				index[h] = i
				m.Banks = append(m.Banks, Bank{Hash: h, PCRs: map[int][]byte{}})
			}
			if _, dup := m.Banks[i].PCRs[pcr]; dup {
				return Manifest{}, &InvalidManifestError{Reason: fmt.Sprintf("PCR %d has two %v digests", pcr, h)}
			}
			m.Banks[i].PCRs[pcr] = d.Val
		}
	}
	if err := m.validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// errUnknownAlg is wrapped by the error hashOf returns.
var errUnknownAlg = errors.New("not a Named Information hash algorithm this platform predicts")

func hashOf(alg int64) (crypto.Hash, error) {
	for h, id := range namedInformation {
		if id == alg {
			return h, nil
		}
	}
	return 0, &InvalidManifestError{Reason: fmt.Sprintf("digest algorithm %d", alg), Err: errUnknownAlg}
}
