package measure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
)

// testPE is a PE32+ EFI application with the 16 data directories a linker
// writes and n sections of 0x200 bytes of 0xcc, the first at 0x400.
func testPE(n int) []byte {
	const opt, table, first, size = 0x98, 0x188, 0x400, 0x200
	pe := make([]byte, first+n*size)
	le := binary.LittleEndian
	le.PutUint16(pe[0:], 0x5a4d)
	le.PutUint32(pe[0x3c:], 0x80)
	copy(pe[0x80:], "PE\x00\x00")
	le.PutUint16(pe[0x84:], 0xaa64)                 // Machine: ARM64
	le.PutUint16(pe[0x86:], uint16(n))              // NumberOfSections
	le.PutUint16(pe[0x94:], table-opt)              // SizeOfOptionalHeader
	le.PutUint16(pe[0x96:], 0x22)                   // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	le.PutUint16(pe[opt:], pe32PlusMagic)           // Magic
	le.PutUint32(pe[opt+16:], 0x1000)               // AddressOfEntryPoint
	le.PutUint32(pe[opt+32:], 0x1000)               // SectionAlignment
	le.PutUint32(pe[opt+36:], 0x200)                // FileAlignment
	le.PutUint32(pe[opt+56:], uint32(0x1000*(n+1))) // SizeOfImage
	le.PutUint32(pe[opt+60:], first)                // SizeOfHeaders
	le.PutUint16(pe[opt+68:], 10)                   // Subsystem: EFI application
	le.PutUint32(pe[opt+108:], 16)                  // NumberOfRvaAndSizes
	for i := 0; i < n; i++ {
		e := pe[table+i*peSectionHeaderSize:]
		copy(e[0:8], fmt.Sprintf(".sect%d", i))
		le.PutUint32(e[8:], size)                  // VirtualSize
		le.PutUint32(e[12:], uint32(0x1000*(i+1))) // VirtualAddress
		le.PutUint32(e[16:], size)                 // SizeOfRawData
		le.PutUint32(e[20:], uint32(first+i*size)) // PointerToRawData
		le.PutUint32(e[36:], 0x40000040)           // INITIALIZED_DATA | MEM_READ
		copy(pe[first+i*size:first+(i+1)*size], bytes.Repeat([]byte{0xcc}, size))
	}
	return pe
}

// peOffsets are the header offsets of a PE32+ test image.
type peOffsets struct {
	checksum, securityDir, sizeOfHeaders, table, sections int
}

func offsetsOf(pe []byte) peOffsets {
	coff := int(binary.LittleEndian.Uint32(pe[0x3c:])) + 4
	opt := coff + 20
	return peOffsets{
		checksum:      opt + 64,
		securityDir:   opt + 144,
		sizeOfHeaders: opt + 60,
		table:         opt + int(binary.LittleEndian.Uint16(pe[coff+16:])),
		sections:      int(binary.LittleEndian.Uint16(pe[coff+2:])),
	}
}

func sectionEntry(pe []byte, i int) []byte {
	t := offsetsOf(pe).table + i*peSectionHeaderSize
	return pe[t : t+peSectionHeaderSize]
}

func sectionRaw(pe []byte, i int) []byte {
	e := sectionEntry(pe, i)
	p, n := binary.LittleEndian.Uint32(e[20:]), binary.LittleEndian.Uint32(e[16:])
	return pe[p : p+n]
}

// ukiFixture is a PE whose sections carry the given names, each filled
// with its own byte so that the contents differ.
func ukiFixture(names ...string) []byte {
	pe := testPE(len(names))
	for i, name := range names {
		e := sectionEntry(pe, i)
		copy(e[0:8], make([]byte, 8))
		copy(e[0:8], name)
		raw := sectionRaw(pe, i)
		for j := range raw {
			raw[j] = byte(0x10 + i)
		}
	}
	return pe
}

func setVirtualSize(pe []byte, i int, size uint32) {
	binary.LittleEndian.PutUint32(sectionEntry(pe, i)[8:], size)
}

func TestAuthenticodeDigestMatchesTheSigner(t *testing.T) {
	keyPath, certPath := authenticodetest.WriteKeyPair(t, t.TempDir())
	signer, err := authenticode.NewFileSigner(context.Background(), keyPath, certPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	if err := signer.Sign(bytes.NewReader(testPE(3)), &signed); err != nil {
		t.Fatal(err)
	}
	got, err := AuthenticodeDigest(crypto.SHA256, signed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// The signer embeds its own digest of the image in the signature's
	// SpcIndirectDataContent: the two computations agree when it is there.
	if !bytes.Contains(signed.Bytes(), got) {
		t.Fatalf("digest %x is not the one the signer embedded", got)
	}
}

func TestAuthenticodeDigestRegions(t *testing.T) {
	pe := testPE(2)
	o := offsetsOf(pe)
	for i, fill := range []byte{0x11, 0x22} {
		raw := sectionRaw(pe, i)
		for j := range raw {
			raw[j] = fill
		}
	}
	// List the sections out of file order and add trailing data and a
	// certificate table.
	headersEnd := int(binary.LittleEndian.Uint32(pe[o.sizeOfHeaders:]))
	first, second := append([]byte(nil), sectionEntry(pe, 0)...), append([]byte(nil), sectionEntry(pe, 1)...)
	copy(sectionEntry(pe, 0), second)
	copy(sectionEntry(pe, 1), first)
	certOffset := len(pe) + 4
	pe = append(pe, []byte("tail")...)
	pe = append(pe, bytes.Repeat([]byte{0xee}, 16)...)
	binary.LittleEndian.PutUint32(pe[o.securityDir:], uint32(certOffset))
	binary.LittleEndian.PutUint32(pe[o.securityDir+4:], 16)

	got, err := AuthenticodeDigest(crypto.SHA256, pe)
	if err != nil {
		t.Fatal(err)
	}
	// sectionRaw(pe, 1) is now the first section in the file.
	want := sum256(pe[:o.checksum], pe[o.checksum+4:o.securityDir], pe[o.securityDir+8:headersEnd],
		sectionRaw(pe, 1), sectionRaw(pe, 0), []byte("tail"))
	if !bytes.Equal(got, want) {
		t.Fatalf("digest %x, want %x", got, want)
	}

	// The checksum, the certificate table entry and the table are not hashed.
	for _, off := range []int{o.checksum, o.securityDir + 3, len(pe) - 1} {
		edited := append([]byte(nil), pe...)
		edited[off] ^= 0xff
		if d, err := AuthenticodeDigest(crypto.SHA256, edited); err != nil || !bytes.Equal(d, got) {
			t.Fatalf("editing byte %d changed the digest (err %v)", off, err)
		}
	}
	edited := append([]byte(nil), pe...)
	sectionRaw(edited, 0)[0] ^= 0xff
	if d, _ := AuthenticodeDigest(crypto.SHA256, edited); bytes.Equal(d, got) {
		t.Fatal("editing a section did not change the digest")
	}

	// Headers that end before the first section put the trailing data's
	// offset inside a section: U-Boot refuses such an image, and so does this.
	gap := append([]byte(nil), pe...)
	binary.LittleEndian.PutUint32(gap[o.sizeOfHeaders:], uint32(o.table+o.sections*peSectionHeaderSize))
	var me *MalformedImageError
	if _, err := AuthenticodeDigest(crypto.SHA256, gap); !errors.As(err, &me) {
		t.Fatalf("a gap after the headers: err %v, want a MalformedImageError", err)
	}
}

func TestAuthenticodeDigestRefusesMalformedImages(t *testing.T) {
	pe := testPE(1)
	pastEnd := append([]byte(nil), pe...)
	binary.LittleEndian.PutUint32(sectionEntry(pastEnd, 0)[16:], uint32(len(pe)))
	badMagic := append([]byte(nil), pe...)
	badMagic[0] = 'X'
	for name, image := range map[string][]byte{
		"empty":                {},
		"not MZ":               badMagic,
		"truncated":            pe[:0x80],
		"section past the end": pastEnd,
	} {
		var me *MalformedImageError
		if _, err := AuthenticodeDigest(crypto.SHA256, image); !errors.As(err, &me) {
			t.Fatalf("%s: err %v, want a MalformedImageError", name, err)
		}
	}
	var ue *UnsupportedBankError
	if _, err := AuthenticodeDigest(crypto.MD4, pe); !errors.As(err, &ue) {
		t.Fatalf("err %v, want an UnsupportedBankError", err)
	}
}

func TestUKIKernel(t *testing.T) {
	uki := ukiFixture(".osrel", ".linux")
	raw := append([]byte(nil), sectionRaw(uki, 1)...)
	setVirtualSize(uki, 1, uint32(len(raw)+16))
	got, err := UKIKernel(uki)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(raw, make([]byte, 16)...); !bytes.Equal(got, want) {
		t.Fatal("the kernel is not the .linux section padded to its VirtualSize")
	}
	var me *MissingInputError
	if _, err := UKIKernel(ukiFixture(".osrel")); !errors.As(err, &me) || me.PCR != 4 {
		t.Fatalf("without .linux: err %v", err)
	}
}

func TestPredictPCR4(t *testing.T) {
	uki, kernel := testPE(2), testPE(1)
	got, err := PredictPCR4(crypto.SHA256, uki, kernel)
	if err != nil {
		t.Fatal(err)
	}
	ukiDigest, _ := AuthenticodeDigest(crypto.SHA256, uki)
	kernelDigest, _ := AuthenticodeDigest(crypto.SHA256, kernel)
	want, _ := Replay(crypto.SHA256, ukiDigest,
		mustHex(t, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba"),
		mustHex(t, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
		kernelDigest)
	if !bytes.Equal(got, want) {
		t.Fatalf("PCR 4 %x, want %x", got, want)
	}

	var me *MissingInputError
	if _, err := PredictPCR4(crypto.SHA256, nil); !errors.As(err, &me) || me.PCR != 4 {
		t.Fatalf("without a boot application: err %v", err)
	}
	var mal *MalformedImageError
	if _, err := PredictPCR4(crypto.SHA256, uki, []byte("not a PE")); !errors.As(err, &mal) {
		t.Fatalf("a malformed loaded image: err %v", err)
	}
}

func TestPredictPCR11(t *testing.T) {
	// File order differs from the stub's; .pcrsig is not measured.
	uki := ukiFixture(".sbat", ".pcrsig", ".linux", ".osrel")
	setVirtualSize(uki, 3, 5)
	got, err := PredictPCR11(crypto.SHA256, uki)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 32)
	for _, ev := range [][]byte{
		[]byte(".linux\x00"), sectionRaw(uki, 2),
		[]byte(".osrel\x00"), sectionRaw(uki, 3)[:5],
		[]byte(".sbat\x00"), sectionRaw(uki, 0),
	} {
		want = sum256(want, sum256(ev))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PCR 11 %x, want %x", got, want)
	}

	// A section without contents is absent to the stub.
	empty := ukiFixture(".linux", ".splash")
	setVirtualSize(empty, 1, 0)
	withoutSplash, _ := PredictPCR11(crypto.SHA256, ukiFixture(".linux"))
	if got, err := PredictPCR11(crypto.SHA256, empty); err != nil || !bytes.Equal(got, withoutSplash) {
		t.Fatalf("an empty .splash was measured (err %v)", err)
	}
}

func TestPredictPCR11RefusesUKIsItCannotPredict(t *testing.T) {
	huge := ukiFixture(".linux")
	setVirtualSize(huge, 0, 1<<30)
	for name, uki := range map[string][]byte{
		"a profile":         ukiFixture(".linux", ".profile"),
		"a duplicate":       ukiFixture(".linux", ".linux"),
		"an oversized size": huge,
		"not a PE":          []byte("not a PE"),
	} {
		var me *MalformedImageError
		if _, err := PredictPCR11(crypto.SHA256, uki); !errors.As(err, &me) {
			t.Fatalf("%s: err %v, want a MalformedImageError", name, err)
		}
	}
	var mi *MissingInputError
	if _, err := PredictPCR11(crypto.SHA256, ukiFixture(".osrel")); !errors.As(err, &mi) || mi.PCR != 11 {
		t.Fatalf("without .linux: err %v", err)
	}
	var ue *UnsupportedBankError
	if _, err := PredictPCR11(crypto.MD4, ukiFixture(".linux")); !errors.As(err, &ue) {
		t.Fatalf("err %v, want an UnsupportedBankError", err)
	}
}

const testUBootVersion = "U-Boot 2024.04-rc1 (Apr 02 2024 - 10:58:58 +0000) rpi"

func TestUBootVersion(t *testing.T) {
	binary := []byte("\x7fELF\x00U-Boot SPL 2024.04 (Apr 02 2024 - 10:58:58 +0000)\x00" +
		"U-Boot 2024.04 is not a version string\x00" + testUBootVersion + "\x00\x01\x02" + testUBootVersion + "\x00")
	got, err := UBootVersion(binary)
	if err != nil {
		t.Fatal(err)
	}
	if got != testUBootVersion {
		t.Fatalf("version %q, want %q", got, testUBootVersion)
	}

	var me *MalformedImageError
	if _, err := UBootVersion([]byte("no version here")); !errors.As(err, &me) {
		t.Fatalf("no version: err %v", err)
	}
	two := []byte(testUBootVersion + "\x00U-Boot 2025.01 (Jan 07 2025 - 00:00:00 +0000)\x00")
	if _, err := UBootVersion(two); !errors.As(err, &me) {
		t.Fatalf("two versions: err %v", err)
	}
}

func TestPredictPCR0(t *testing.T) {
	got, err := PredictPCR0(crypto.SHA256, testUBootVersion)
	if err != nil {
		t.Fatal(err)
	}
	version := sha256.Sum256([]byte(testUBootVersion + "\x00"))
	want := sum256(sum256(make([]byte, 32), version[:]),
		mustHex(t, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"))
	if !bytes.Equal(got, want) {
		t.Fatalf("PCR 0 %x, want %x", got, want)
	}
	var me *MissingInputError
	if _, err := PredictPCR0(crypto.SHA256, ""); !errors.As(err, &me) || me.PCR != 0 {
		t.Fatalf("without a version: err %v", err)
	}
}
