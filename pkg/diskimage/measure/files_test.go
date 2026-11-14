package measure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testOwner is uboot.DefaultOwnerGUID, in the byte order U-Boot's lists
// carry it (mkesl.py's uuid.bytes_le).
const testOwner = "7e5a1c6e-0b3f-4a5e-9c2d-3f1a2b4c5d6e"

var testOwnerBytes = []byte{0x6e, 0x1c, 0x5a, 0x7e, 0x3f, 0x0b, 0x5e, 0x4a, 0x9c, 0x2d, 0x3f, 0x1a, 0x2b, 0x4c, 0x5d, 0x6e}

// writeImageFiles writes a U-Boot binary, a UKI and PK/KEK/DB certificates
// under a temp dir and returns the files and each certificate's DER.
func writeImageFiles(t *testing.T) (ImageFiles, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	certDir := filepath.Join(dir, "secure-boot-certs")
	if err := os.Mkdir(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ders := map[string][]byte{}
	for i, name := range []string{"PK.crt", "KEK.crt", "DB.crt"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		ders[name] = der
		if err := os.WriteFile(filepath.Join(certDir, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	uki, _ := testUKI("ro")
	files := ImageFiles{UBoot: filepath.Join(dir, "u-boot.bin"), UKI: filepath.Join(dir, "BOOTAA64.EFI"), CertDir: certDir, OwnerGUID: testOwner}
	if err := os.WriteFile(files.UBoot, []byte("\x00"+testUBootVersion+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files.UKI, uki, 0o644); err != nil {
		t.Fatal(err)
	}
	return files, ders
}

// testESL is the one-certificate EFI_SIGNATURE_LIST mkesl.py writes.
func testESL(der []byte) []byte {
	x509Type := []byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}
	out := append([]byte{}, x509Type...)
	out = binary.LittleEndian.AppendUint32(out, uint32(28+16+len(der)))
	out = binary.LittleEndian.AppendUint32(out, 0)
	out = binary.LittleEndian.AppendUint32(out, uint32(16+len(der)))
	out = append(out, testOwnerBytes...)
	return append(out, der...)
}

func TestReadImage(t *testing.T) {
	files, ders := writeImageFiles(t)
	img, err := ReadImage(files)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string][]byte{"PK.crt": img.SecureBoot.PK, "KEK.crt": img.SecureBoot.KEK, "DB.crt": img.SecureBoot.DB} {
		if want := testESL(ders[name]); !bytes.Equal(got, want) {
			t.Errorf("%s list %x, want %x", name, got, want)
		}
	}
	if img.SecureBoot.DBX != nil {
		t.Errorf("dbx %x, want none: U-Boot preseeds no dbx", img.SecureBoot.DBX)
	}
	if want := append(append([]byte{}, testOwnerBytes...), ders["DB.crt"]...); !bytes.Equal(img.Authority, want) {
		t.Errorf("authority %x, want the owner and the DB certificate", img.Authority)
	}
	if !bytes.HasPrefix(img.UBoot, []byte("\x00U-Boot ")) || len(img.UKI) == 0 {
		t.Fatalf("U-Boot %q, UKI %d bytes", img.UBoot, len(img.UKI))
	}
	if _, err := Predict(img); err != nil {
		t.Fatalf("predicting the read image: %v", err)
	}
}

func TestReadImageRefusesMissingInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, f *ImageFiles)
		pcr  int
	}{
		{"no U-Boot", func(t *testing.T, f *ImageFiles) { f.UBoot = "" }, 0},
		{"U-Boot missing", func(t *testing.T, f *ImageFiles) { f.UBoot += ".gone" }, 0},
		{"UKI empty", func(t *testing.T, f *ImageFiles) {
			if err := os.WriteFile(f.UKI, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, 4},
		{"no owner", func(t *testing.T, f *ImageFiles) { f.OwnerGUID = "" }, 7},
		{"no certificate dir", func(t *testing.T, f *ImageFiles) { f.CertDir = "" }, 7},
		{"no DB certificate", func(t *testing.T, f *ImageFiles) {
			if err := os.Remove(filepath.Join(f.CertDir, "DB.crt")); err != nil {
				t.Fatal(err)
			}
		}, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, _ := writeImageFiles(t)
			tc.edit(t, &files)
			var me *MissingInputError
			if _, err := ReadImage(files); !errors.As(err, &me) || me.PCR != tc.pcr {
				t.Fatalf("err %v, want a missing PCR %d input", err, tc.pcr)
			}
		})
	}

	files, _ := writeImageFiles(t)
	if err := os.WriteFile(filepath.Join(files.CertDir, "KEK.crt"), []byte("not PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mal *MalformedImageError
	if _, err := ReadImage(files); !errors.As(err, &mal) {
		t.Fatalf("a KEK that is not PEM: err %v", err)
	}
	files, _ = writeImageFiles(t)
	files.OwnerGUID = "not-a-guid"
	if _, err := ReadImage(files); !errors.As(err, &mal) {
		t.Fatalf("a malformed owner GUID: err %v", err)
	}
}
