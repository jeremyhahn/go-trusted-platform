package measure

import (
	"bytes"
	"crypto"
	_ "crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"
)

// testUKI is a UKI with a .cmdline, an .initrd and, last, a .linux section
// that holds testPE(1) as the kernel.
func testUKI(cmdline string) (uki, kernel []byte) {
	kernel = testPE(1)
	uki = ukiFixture(".cmdline", ".initrd", ".linux")
	raw := sectionRaw(uki, 0)
	copy(raw, make([]byte, len(raw)))
	copy(raw, cmdline)
	binary.LittleEndian.PutUint32(sectionEntry(uki, 0)[8:], uint32(len(cmdline)))
	linuxAt := binary.LittleEndian.Uint32(sectionEntry(uki, 2)[20:])
	uki = append(uki[:linuxAt:linuxAt], kernel...)
	e := sectionEntry(uki, 2)
	binary.LittleEndian.PutUint32(e[8:], uint32(len(kernel)))
	binary.LittleEndian.PutUint32(e[16:], uint32(len(kernel)))
	return uki, kernel
}

func testImage() (Image, []byte) {
	uki, kernel := testUKI("root=/dev/mapper/root ro")
	return Image{
		UBoot:      []byte("\x00" + testUBootVersion + "\x00"),
		UKI:        uki,
		SecureBoot: SecureBootVariables{PK: []byte("pk"), KEK: []byte("kek"), DB: []byte("db")},
		Authority:  SignatureData(NewGUID(1, 2, 3, [8]byte{4}), []byte("db certificate")),
	}, kernel
}

func TestStubLoadOptions(t *testing.T) {
	if got := StubLoadOptions(nil); got != nil {
		t.Fatalf("no .cmdline: %x, want none", got)
	}
	want := []byte{'r', 0, 'o', 0, ' ', 0, 0xe9, 0, 0, 0}
	if got := StubLoadOptions([]byte("ro é\x00\x00padding")); !bytes.Equal(got, want) {
		t.Fatalf("load options %x, want %x", got, want)
	}
}

func TestPredict(t *testing.T) {
	img, kernel := testImage()
	banks, err := Predict(img, crypto.SHA256, crypto.SHA384, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(banks) != 2 || banks[0].Hash != crypto.SHA256 || banks[1].Hash != crypto.SHA384 {
		t.Fatalf("banks %+v, want sha256 then sha384, once each", banks)
	}
	initrd := bytes.Repeat([]byte{0x11}, 0x200)
	options := StubLoadOptions([]byte("root=/dev/mapper/root ro"))
	for _, bank := range banks {
		h := bank.Hash
		pcr0, _ := PredictPCR0(h, testUBootVersion)
		pcr4, _ := PredictPCR4(h, img.UKI, kernel)
		pcr7, _ := PredictPCR7(h, img.SecureBoot, img.Authority)
		pcr9, _ := PredictPCR9(h, options, initrd)
		want := map[int][]byte{0: pcr0, 4: pcr4, 7: pcr7, 9: pcr9}
		if len(bank.PCRs) != len(ManifestPCRs) {
			t.Fatalf("%v: PCRs %v, want %v", h, bank.PCRs, ManifestPCRs)
		}
		for _, pcr := range ManifestPCRs {
			if got := bank.PCRs[pcr]; !bytes.Equal(got, want[pcr]) || len(got) != h.Size() {
				t.Errorf("%v PCR %d %x, want %x", h, pcr, got, want[pcr])
			}
		}
	}

	defaulted, err := Predict(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(defaulted) != 1 || defaulted[0].Hash != crypto.SHA256 || !bytes.Equal(defaulted[0].PCRs[4], banks[0].PCRs[4]) {
		t.Fatalf("no bank given: %+v, want sha256", defaulted)
	}
}

func TestPredictRefusesMissingInputs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*Image)
		pcr   int
		input string
	}{
		{"no .initrd", func(img *Image) { copy(sectionEntry(img.UKI, 1)[0:8], ".rodata\x00") }, 9, "the UKI's .initrd section"},
		{"no .linux", func(img *Image) { copy(sectionEntry(img.UKI, 2)[0:8], ".rodata\x00") }, 4, "the UKI's .linux section"},
		{"no authority", func(img *Image) { img.Authority = nil }, 7, "authority"},
		{"no db", func(img *Image) { img.SecureBoot.DB = nil }, 7, "db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img, _ := testImage()
			tc.edit(&img)
			var me *MissingInputError
			if _, err := Predict(img); !errors.As(err, &me) || me.PCR != tc.pcr || me.Input != tc.input {
				t.Fatalf("err %v, want PCR %d missing %q", err, tc.pcr, tc.input)
			}
		})
	}
	img, _ := testImage()
	img.UBoot = []byte("no version here")
	var mal *MalformedImageError
	if _, err := Predict(img); !errors.As(err, &mal) {
		t.Fatalf("a U-Boot without a version: err %v", err)
	}
	img, _ = testImage()
	var unsupported *UnsupportedBankError
	if _, err := Predict(img, crypto.Hash(0)); !errors.As(err, &unsupported) {
		t.Fatalf("an unknown bank: err %v", err)
	}
}
