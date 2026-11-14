package measure

import (
	"bytes"
	"crypto"
	"unicode/utf16"
)

// ManifestPCRs are the PCRs an image determines and its manifest carries:
// the U-Boot version (0), the UKI and its kernel (4), the Secure Boot state
// (7) and the initrd (9). PCRs 1, 2, 5 and 11 join them only once the
// event-log replay shows that a boot of the image always gives the
// predicted value (docs/factory-image/architecture.md §8).
var ManifestPCRs = []int{0, 4, 7, 9}

// Image is what the build writes to the card that the boot chain measures.
type Image struct {
	// UBoot is the U-Boot binary (u-boot.bin, kernel8.img on the Pi).
	UBoot []byte
	// UKI is the signed UKI, EFI/BOOT/BOOTAA64.EFI.
	UKI []byte
	// SecureBoot holds PK, KEK, db and dbx as U-Boot preseeds them.
	SecureBoot SecureBootVariables
	// Authority is the db entry that verifies the UKI and its kernel, a
	// SignatureData: one EV_EFI_VARIABLE_AUTHORITY, as both images verify
	// against the same entry.
	Authority []byte
}

// Bank is one bank's predicted values of ManifestPCRs.
type Bank struct {
	Hash crypto.Hash
	PCRs map[int][]byte
}

// Predict replays ManifestPCRs for every bank, sha256 when none is given,
// from the image's bytes. A missing input fails every bank: the build never
// writes a partial manifest.
func Predict(img Image, banks ...crypto.Hash) ([]Bank, error) {
	if len(banks) == 0 {
		banks = []crypto.Hash{crypto.SHA256}
	}
	version, err := UBootVersion(img.UBoot)
	if err != nil {
		return nil, err
	}
	kernel, err := UKIKernel(img.UKI)
	if err != nil {
		return nil, err
	}
	sections, err := ukiSections(img.UKI)
	if err != nil {
		return nil, err
	}
	initrd, ok := sections[".initrd"]
	if !ok {
		return nil, &MissingInputError{PCR: 9, Input: "the UKI's .initrd section"}
	}
	if len(img.Authority) == 0 {
		return nil, &MissingInputError{PCR: 7, Input: "authority"}
	}
	loadOptions := StubLoadOptions(sections[".cmdline"])

	out := make([]Bank, 0, len(banks))
	seen := make(map[crypto.Hash]bool, len(banks))
	for _, h := range banks {
		if seen[h] {
			continue
		}
		seen[h] = true
		pcrs := make(map[int][]byte, len(ManifestPCRs))
		if pcrs[0], err = PredictPCR0(h, version); err != nil {
			return nil, err
		}
		if pcrs[4], err = PredictPCR4(h, img.UKI, kernel); err != nil {
			return nil, err
		}
		if pcrs[7], err = PredictPCR7(h, img.SecureBoot, img.Authority); err != nil {
			return nil, err
		}
		if pcrs[9], err = PredictPCR9(h, loadOptions, initrd); err != nil {
			return nil, err
		}
		out = append(out, Bank{Hash: h, PCRs: pcrs})
	}
	return out, nil
}

// StubLoadOptions are the load options systemd-stub hands the kernel for a
// UKI's .cmdline: the command line up to its first NUL as NUL-terminated
// UTF-16LE. The Linux EFI stub measures them into PCR 9. A UKI without a
// command line passes none (nil).
func StubLoadOptions(cmdline []byte) []byte {
	if cmdline == nil {
		return nil
	}
	if i := bytes.IndexByte(cmdline, 0); i >= 0 {
		cmdline = cmdline[:i]
	}
	units := utf16.Encode([]rune(string(cmdline)))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return append(out, 0, 0)
}
