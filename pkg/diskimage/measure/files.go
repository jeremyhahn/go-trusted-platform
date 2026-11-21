package measure

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// ImageFiles names the build's files an Image is read from.
type ImageFiles struct {
	// UBoot is the U-Boot build's u-boot.bin, the binary the card carries.
	UBoot string
	// UKI is the signed UKI as written to the image's EFI system partition.
	UKI string
	// CertDir holds PK.crt, KEK.crt and DB.crt (PEM), the certificates
	// U-Boot's build preseeds (iso.SecureBootMaterial.CertDir).
	CertDir string
	// OwnerGUID is the SignatureOwner of U-Boot's preseeded lists, the U-Boot
	// manifest's owner_guid.
	OwnerGUID string
}

// ReadImage reads the files an Image is predicted from. PK, KEK and db are
// rebuilt as the one-certificate EFI_SIGNATURE_LISTs U-Boot's build preseeds
// (build/docker/uboot-builder/mkesl.py), dbx is empty because U-Boot
// preseeds none, and the authority is db's one entry. A missing or
// unreadable file is a MissingInputError naming it.
func ReadImage(files ImageFiles) (Image, error) {
	var img Image
	var err error
	if img.UBoot, err = readInput(0, files.UBoot); err != nil {
		return Image{}, err
	}
	if img.UKI, err = readInput(4, files.UKI); err != nil {
		return Image{}, err
	}
	if files.OwnerGUID == "" {
		return Image{}, &MissingInputError{PCR: 7, Input: "the SignatureOwner GUID"}
	}
	owner, err := uefi.ParseGUID(files.OwnerGUID)
	if err != nil {
		return Image{}, &MalformedImageError{Reason: fmt.Sprintf("SignatureOwner GUID %q: %v", files.OwnerGUID, err)}
	}
	if files.CertDir == "" {
		return Image{}, &MissingInputError{PCR: 7, Input: "the Secure Boot certificate directory"}
	}
	certs := make(map[string][]byte, 3)
	for _, name := range []string{"PK.crt", "KEK.crt", "DB.crt"} {
		path := filepath.Join(files.CertDir, name)
		data, err := readInput(7, path)
		if err != nil {
			return Image{}, err
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return Image{}, &MalformedImageError{Reason: path + " is not a PEM certificate"}
		}
		certs[name] = block.Bytes
	}
	list := func(name string) []byte { return uefi.NewSignatureListFromCert(certs[name], owner).Bytes() }
	img.SecureBoot = SecureBootVariables{PK: list("PK.crt"), KEK: list("KEK.crt"), DB: list("DB.crt")}
	img.Authority = SignatureData(NewGUID(owner.Data1, owner.Data2, owner.Data3, owner.Data4), certs["DB.crt"])
	return img, nil
}

func readInput(pcr int, path string) ([]byte, error) {
	if path == "" {
		return nil, &MissingInputError{PCR: pcr, Input: "a file path"}
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, &MissingInputError{PCR: pcr, Input: path}
	}
	return data, nil
}
