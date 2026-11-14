package measure

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"sort"
)

// peImage is what the Authenticode digest and systemd-stub's section
// measurements read from a PE/COFF image.
type peImage struct {
	data              []byte
	checksumOffset    uint64
	securityDirOffset uint64
	sizeOfHeaders     uint64
	certTableSize     uint64
	sections          []peSection
}

// peSection is one section table entry.
type peSection struct {
	name             string
	virtualSize      uint64
	sizeOfRawData    uint64
	pointerToRawData uint64
}

const (
	peSectionHeaderSize = 40
	pe32Magic           = 0x10b
	pe32PlusMagic       = 0x20b
)

func parsePE(data []byte) (*peImage, error) {
	bad := func(format string, a ...any) error {
		return &MalformedImageError{Reason: fmt.Sprintf(format, a...)}
	}
	size := uint64(len(data))
	if size < 0x40 || binary.LittleEndian.Uint16(data[0:2]) != 0x5a4d {
		return nil, bad("no MZ header")
	}
	peOff := uint64(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	coff := peOff + 4
	opt := coff + 20
	if opt+2 > size || binary.LittleEndian.Uint32(data[peOff:]) != 0x00004550 {
		return nil, bad("no PE signature")
	}
	numSections := uint64(binary.LittleEndian.Uint16(data[coff+2:]))
	optSize := uint64(binary.LittleEndian.Uint16(data[coff+16:]))
	var secDir uint64
	switch binary.LittleEndian.Uint16(data[opt:]) {
	case pe32Magic:
		secDir = opt + 128
	case pe32PlusMagic:
		secDir = opt + 144
	default:
		return nil, bad("unknown optional header magic")
	}
	if secDir+8 > opt+optSize || opt+optSize > size {
		return nil, bad("the optional header has no certificate table entry")
	}
	img := &peImage{
		data:              data,
		checksumOffset:    opt + 64,
		securityDirOffset: secDir,
		sizeOfHeaders:     uint64(binary.LittleEndian.Uint32(data[opt+60:])),
		certTableSize:     uint64(binary.LittleEndian.Uint32(data[secDir+4:])),
	}
	table := opt + optSize
	if table+numSections*peSectionHeaderSize > size {
		return nil, bad("the section table runs past the end of the file")
	}
	if img.sizeOfHeaders < secDir+8 || img.sizeOfHeaders > size {
		return nil, bad("SizeOfHeaders %d is outside the headers", img.sizeOfHeaders)
	}
	if img.certTableSize > size {
		return nil, bad("the certificate table is larger than the file")
	}
	for i := uint64(0); i < numSections; i++ {
		h := data[table+i*peSectionHeaderSize:]
		s := peSection{
			name:             string(bytes.TrimRight(h[0:8], "\x00")),
			virtualSize:      uint64(binary.LittleEndian.Uint32(h[8:])),
			sizeOfRawData:    uint64(binary.LittleEndian.Uint32(h[16:])),
			pointerToRawData: uint64(binary.LittleEndian.Uint32(h[20:])),
		}
		if s.pointerToRawData+s.sizeOfRawData > size {
			return nil, bad("section %q runs past the end of the file", s.name)
		}
		img.sections = append(img.sections, s)
	}
	return img, nil
}

// AuthenticodeDigest is the PE/COFF image hash (Authenticode, Microsoft
// PE/COFF specification §"Calculating the PE image hash") that UEFI firmware
// extends into PCR 4 as an EV_EFI_BOOT_SERVICES_APPLICATION event: the
// headers without the checksum and the certificate table entry, the
// sections in file order, then any data after them except the certificate
// table. It is the hash U-Boot's efi_image_parse regions describe.
func AuthenticodeDigest(h crypto.Hash, image []byte) ([]byte, error) {
	if err := checkHash(h); err != nil {
		return nil, err
	}
	img, err := parsePE(image)
	if err != nil {
		return nil, err
	}
	d := img.data
	w := h.New()
	_, _ = w.Write(d[:img.checksumOffset])
	_, _ = w.Write(d[img.checksumOffset+4 : img.securityDirOffset])
	_, _ = w.Write(d[img.securityDirOffset+8 : img.sizeOfHeaders])
	hashed := img.sizeOfHeaders

	sections := make([]peSection, 0, len(img.sections))
	for _, s := range img.sections {
		if s.sizeOfRawData > 0 {
			sections = append(sections, s)
		}
	}
	sort.SliceStable(sections, func(i, j int) bool {
		return sections[i].pointerToRawData < sections[j].pointerToRawData
	})
	var sectionsEnd uint64
	for _, s := range sections {
		_, _ = w.Write(d[s.pointerToRawData : s.pointerToRawData+s.sizeOfRawData])
		hashed += s.sizeOfRawData
		sectionsEnd = max(sectionsEnd, s.pointerToRawData+s.sizeOfRawData)
	}
	// The trailing data starts at the count of bytes hashed, as the
	// specification and U-Boot have it. When the sections do not follow the
	// headers back to back, that offset falls inside a section, and U-Boot
	// refuses the image for the overlap.
	if end := uint64(len(d)) - img.certTableSize; hashed < end {
		if hashed < sectionsEnd {
			return nil, &MalformedImageError{Reason: "the sections do not follow the headers back to back"}
		}
		_, _ = w.Write(d[hashed:end])
	}
	return w.Sum(nil), nil
}

// sectionMemory is a section as the loader maps it: VirtualSize bytes, the
// raw data cut to that size or padded with zeros to it.
func (img *peImage) sectionMemory(s peSection) []byte {
	out := make([]byte, s.virtualSize)
	raw := img.data[s.pointerToRawData : s.pointerToRawData+s.sizeOfRawData]
	copy(out, raw)
	return out
}

// ukiSections maps the UKI sections that systemd-stub reads to their
// in-memory contents. A section without contents is left out, as the stub
// treats it as absent. A section that appears twice is refused.
func ukiSections(uki []byte) (map[string][]byte, error) {
	img, err := parsePE(uki)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(img.sections))
	for _, s := range img.sections {
		if _, dup := out[s.name]; dup {
			return nil, &MalformedImageError{Reason: fmt.Sprintf("section %q appears twice", s.name)}
		}
		if s.virtualSize == 0 {
			continue
		}
		if s.virtualSize > uint64(len(uki)) {
			return nil, &MalformedImageError{Reason: fmt.Sprintf("section %q maps %d bytes, more than the file holds", s.name, s.virtualSize)}
		}
		out[s.name] = img.sectionMemory(s)
	}
	return out, nil
}

// UKIKernel is the kernel a UKI carries, as systemd-stub hands it to
// LoadImage: the .linux section's in-memory contents.
func UKIKernel(uki []byte) ([]byte, error) {
	sections, err := ukiSections(uki)
	if err != nil {
		return nil, err
	}
	kernel, ok := sections[".linux"]
	if !ok {
		return nil, &MissingInputError{PCR: 4, Input: "the UKI's .linux section"}
	}
	return kernel, nil
}
