package measure

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// testManifest has a sha256 and a sha384 bank, each PCR filled with its
// index so the encoding can be read.
func testManifest(t *testing.T) Manifest {
	t.Helper()
	id, err := ManifestTagID(bytes.Repeat([]byte{0xab}, sha256.Size))
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{TagID: id, Model: "rpi/rpi4"}
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		b := Bank{Hash: h, PCRs: map[int][]byte{}}
		for _, pcr := range ManifestPCRs {
			b.PCRs[pcr] = bytes.Repeat([]byte{byte(pcr)}, h.Size())
		}
		m.Banks = append(m.Banks, b)
	}
	return m
}

func TestManifestRoundTrip(t *testing.T) {
	m := testManifest(t)
	data, err := EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("decoded %+v, want %+v", got, m)
	}
	again, err := EncodeManifest(got)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatalf("re-encoding is not byte-identical (err %v)", err)
	}
}

// The encoding is the CoRIM shape architecture.md §8 sets out: a
// tagged-unsigned-corim-map whose id is the tag identity, holding one CoMID
// with one reference triple for vendor go-trusted-platform and the model,
// one measurement per PCR keyed by its index, one digest per bank in the
// Named Information registry's algorithm identifiers.
func TestEncodeManifestShape(t *testing.T) {
	m := testManifest(t)
	data, err := EncodeManifest(Manifest{TagID: m.TagID, Model: m.Model, Banks: []Bank{{Hash: crypto.SHA256, PCRs: map[int][]byte{
		0: bytes.Repeat([]byte{0}, 32), 4: bytes.Repeat([]byte{4}, 32), 7: bytes.Repeat([]byte{7}, 32), 9: bytes.Repeat([]byte{9}, 32),
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	var outer cbor.RawTag
	if err := cbor.Unmarshal(data, &outer); err != nil || outer.Number != TagUnsignedCoRIM {
		t.Fatalf("outer tag %d (err %v), want %d", outer.Number, err, TagUnsignedCoRIM)
	}
	var cm struct {
		ID   []byte        `cbor:"0,keyasint"`
		Tags []cbor.RawTag `cbor:"1,keyasint"`
	}
	if err := cbor.Unmarshal(outer.Content, &cm); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cm.ID, m.TagID[:]) || len(cm.Tags) != 1 || cm.Tags[0].Number != TagCoMID {
		t.Fatalf("corim-map id %x, tags %+v", cm.ID, cm.Tags)
	}
	var tag []byte
	if err := cbor.Unmarshal(cm.Tags[0].Content, &tag); err != nil {
		t.Fatal(err)
	}
	diag, err := cbor.Diagnose(tag)
	if err != nil {
		t.Fatal(err)
	}
	hexOf := func(b byte) string {
		return strings.Repeat(string("0123456789abcdef"[b>>4])+string("0123456789abcdef"[b&15]), 32)
	}
	id := strings.ReplaceAll(m.TagID.String(), "-", "")
	want := `{1: {0: h'` + id + `'}, 4: {0: [[{0: {1: "go-trusted-platform", 2: "rpi/rpi4"}}, [` +
		`{0: 0, 1: {2: [[1, h'` + hexOf(0) + `']]}}, ` +
		`{0: 4, 1: {2: [[1, h'` + hexOf(4) + `']]}}, ` +
		`{0: 7, 1: {2: [[1, h'` + hexOf(7) + `']]}}, ` +
		`{0: 9, 1: {2: [[1, h'` + hexOf(9) + `']]}}]]]}}`
	if diag != want {
		t.Fatalf("CoMID\n got %s\nwant %s", diag, want)
	}
}

func TestManifestTagID(t *testing.T) {
	a := bytes.Repeat([]byte{1}, sha256.Size)
	id, err := ManifestTagID(a)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := ManifestTagID(a); again != id {
		t.Errorf("the same image got two tags: %v, %v", id, again)
	}
	if id.Version() != 8 || id.Variant() != uuid.RFC4122 {
		t.Errorf("tag %v is version %d variant %v, want an RFC 9562 version 8", id, id.Version(), id.Variant())
	}
	other, _ := ManifestTagID(bytes.Repeat([]byte{2}, sha256.Size))
	if other == id {
		t.Error("two images got the same tag")
	}
	var me *InvalidManifestError
	if _, err := ManifestTagID(a[:20]); !errors.As(err, &me) {
		t.Errorf("a 20-byte image digest: err %v", err)
	}
}

func TestEncodeManifestRefusesAnIncompleteManifest(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(m *Manifest)
		want string
	}{
		{"no tag identity", func(m *Manifest) { m.TagID = uuid.Nil }, "no tag identity"},
		{"no model", func(m *Manifest) { m.Model = "" }, "no model"},
		{"no bank", func(m *Manifest) { m.Banks = nil }, "no PCR bank"},
		{"a bank without PCR 7", func(m *Manifest) { delete(m.Banks[1].PCRs, 7) }, "the SHA-384 bank has no PCR 7"},
		{"a runtime PCR", func(m *Manifest) { m.Banks[0].PCRs[10] = make([]byte, 32) }, "PCR 10, which the image does not determine"},
		{"a short digest", func(m *Manifest) { m.Banks[0].PCRs[4] = make([]byte, 20) }, "PCR 4 is 20 bytes"},
		{"a bank twice", func(m *Manifest) { m.Banks[1] = m.Banks[0] }, "the SHA-256 bank appears twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testManifest(t)
			tc.edit(&m)
			data, err := EncodeManifest(m)
			var me *InvalidManifestError
			if !errors.As(err, &me) || !strings.Contains(err.Error(), tc.want) || data != nil {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	m := testManifest(t)
	m.Banks[0].Hash = crypto.SHA1
	var ub *UnsupportedBankError
	if _, err := EncodeManifest(m); !errors.As(err, &ub) || ub.Hash != crypto.SHA1 {
		t.Fatalf("a SHA-1 bank, which has no Named Information id: err %v", err)
	}
}

// encodeRaw encodes c inside a CoRIM the way EncodeManifest does, so a test
// can hand DecodeManifest a CoMID EncodeManifest would never write.
func encodeRaw(t *testing.T, number uint64, c comid) []byte {
	t.Helper()
	tag, err := encMode.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	out, err := encMode.Marshal(cbor.Tag{Number: number, Content: corimMap{ID: c.TagIdentity.TagID, Tags: []cbor.Tag{{Number: TagCoMID, Content: tag}}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func validComid(t *testing.T) comid {
	t.Helper()
	m := testManifest(t)
	data, err := EncodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	var outer cbor.RawTag
	var cm corimMapIn
	var raw []byte
	var c comid
	for _, step := range []error{
		cbor.Unmarshal(data, &outer), cbor.Unmarshal(outer.Content, &cm),
		cbor.Unmarshal(cm.Tags[0].Content, &raw), cbor.Unmarshal(raw, &c),
	} {
		if step != nil {
			t.Fatal(step)
		}
	}
	return c
}

func TestDecodeManifestRefusesAnythingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		data func(t *testing.T) []byte
		want string
	}{
		{"not CBOR", func(*testing.T) []byte { return []byte{0xff} }, "not a tagged CoRIM"},
		{"a signed CoRIM", func(t *testing.T) []byte { return encodeRaw(t, 18, validComid(t)) }, "CBOR tag 18"},
		{"another vendor", func(t *testing.T) []byte {
			c := validComid(t)
			c.Triples.Reference[0].Env.Class.Vendor = "someone-else"
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, `vendor "someone-else"`},
		{"an anonymous measurement", func(t *testing.T) []byte {
			c := validComid(t)
			c.Triples.Reference[0].Claims[1].Key = nil
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "a measurement has no PCR index"},
		{"an unknown digest algorithm", func(t *testing.T) []byte {
			c := validComid(t)
			c.Triples.Reference[0].Claims[0].Val.Digests[0].Alg = 2
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "digest algorithm 2"},
		{"a PCR missing from one bank", func(t *testing.T) []byte {
			c := validComid(t)
			c.Triples.Reference[0].Claims[2].Val.Digests = c.Triples.Reference[0].Claims[2].Val.Digests[:1]
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "the SHA-384 bank has no PCR 7"},
		{"a PCR measured twice", func(t *testing.T) []byte {
			c := validComid(t)
			claims := &c.Triples.Reference[0].Claims
			*claims = append(*claims, (*claims)[0])
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "PCR 0 has two SHA-256 digests"},
		{"two reference triples", func(t *testing.T) []byte {
			c := validComid(t)
			c.Triples.Reference = append(c.Triples.Reference, c.Triples.Reference[0])
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "exactly one reference triple"},
		{"a tag identity that is not a UUID", func(t *testing.T) []byte {
			c := validComid(t)
			c.TagIdentity.TagID = []byte("short")
			return encodeRaw(t, TagUnsignedCoRIM, c)
		}, "the tag identity is not a UUID"},
		{"a CoRIM id that is not the tag identity", func(t *testing.T) []byte {
			c := validComid(t)
			tag, _ := encMode.Marshal(c)
			out, _ := encMode.Marshal(cbor.Tag{Number: TagUnsignedCoRIM, Content: corimMap{ID: make([]byte, 16), Tags: []cbor.Tag{{Number: TagCoMID, Content: tag}}}})
			return out
		}, "the CoRIM id is not the CoMID's tag identity"},
		{"two CoMIDs", func(t *testing.T) []byte {
			tag, _ := encMode.Marshal(validComid(t))
			out, _ := encMode.Marshal(cbor.Tag{Number: TagUnsignedCoRIM, Content: corimMap{ID: make([]byte, 16), Tags: []cbor.Tag{{Number: TagCoMID, Content: tag}, {Number: TagCoMID, Content: tag}}}})
			return out
		}, "exactly one CoMID"},
		{"a duplicate map key", func(*testing.T) []byte {
			// 501({0: h'', 0: h''})
			return []byte{0xd9, 0x01, 0xf5, 0xa2, 0x00, 0x40, 0x00, 0x40}
		}, "decoding the CoRIM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := DecodeManifest(tc.data(t))
			var me *InvalidManifestError
			if !errors.As(err, &me) || !strings.Contains(err.Error(), tc.want) || m.Banks != nil {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}
