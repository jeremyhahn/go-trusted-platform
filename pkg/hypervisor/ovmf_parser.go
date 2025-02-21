//go:build libvirt

package hypervisor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxDataSize    = 0x100000
	defaultHdrSize = 0x48
	minHeaderSize  = 32
)

// EFI_GUID represents the EFI GUID structure.
type EFI_GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// EFIVariable represents a single EFI variable.
type EFIVariable struct {
	VendorGUID EFI_GUID `json:"vendor_guid"`
	Name       string   `json:"name"`
	Attributes uint32   `json:"attributes"`
	Value      string   `json:"value"`
	Data       []byte   `json:"-"`
}

// OVMFHeader represents the header of the variable store.
type OVMFHeader struct {
	Signature          uint32
	Revision           uint16
	HeaderSize         uint16
	Reserved           uint32
	VariableStoreSize  uint64
	LastVariableOffset uint64
	// The rest of the header is ignored
}

// OVMFParser handles parsing of the OVMF variable store file.
type OVMFParser struct {
	Filename  string
	Header    OVMFHeader
	Variables []EFIVariable
}

// ParseUEFIVars parses the OVMF_VARS.fd file and returns the UEFI variables.
func ParseUEFIVars(filename string) ([]EFIVariable, error) {
	parser := NewOVMFParser(filename)
	if err := parser.Parse(); err != nil {
		return nil, err
	}
	return parser.Variables, nil
}

// NewOVMFParser creates a new instance of OVMFParser.
func NewOVMFParser(filename string) *OVMFParser {
	return &OVMFParser{Filename: filename}
}

// Parse reads the file, parses the header, and then parses variable entries.
func (p *OVMFParser) Parse() error {
	data, err := ioutil.ReadFile(p.Filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Use fixed header offset of 0 and default header size
	if len(data) < defaultHdrSize {
		return fmt.Errorf("file too small for header")
	}

	hdrData := data[:defaultHdrSize]
	hdrReader := bytes.NewReader(hdrData)
	var hdr OVMFHeader
	if err := binary.Read(hdrReader, binary.LittleEndian, &hdr); err != nil {
		return fmt.Errorf("failed to read header: %v", err)
	}
	if hdr.HeaderSize < minHeaderSize || hdr.HeaderSize > uint16(defaultHdrSize) {
		// Fallback: if header size is zero or invalid, use default value.
		log.Println("Header size is invalid; using default header size")
		hdr.HeaderSize = defaultHdrSize
	}
	p.Header = hdr

	varRegionStart := int(hdr.HeaderSize)
	if varRegionStart >= len(data) {
		return fmt.Errorf("header size exceeds file size")
	}

	region := data[varRegionStart:]
	vars, _ := parseVariables(region)
	p.Variables = vars
	log.Printf("Total Variables Parsed: %d", len(vars))
	return nil
}

// parseVariables parses the variable store region.
func parseVariables(buf []byte) ([]EFIVariable, error) {
	var vars []EFIVariable
	rdr := bytes.NewReader(buf)
	for {
		startPos, _ := rdr.Seek(0, io.SeekCurrent)
		// Need at least 28 bytes for variable header (GUID (16) + Attributes (4) + NameSize (4) + DataSize (4))
		if rdr.Len() < 28 {
			break
		}

		// Peek at the first 2 bytes for marker 0x55AA.
		marker := make([]byte, 2)
		if _, err := rdr.Read(marker); err != nil {
			break
		}
		// Rewind after peek.
		rdr.Seek(startPos, io.SeekStart)
		if binary.LittleEndian.Uint16(marker) != 0x55AA {
			// No valid variable marker found; end of variable list.
			break
		}

		// Read variable header.
		var guid EFI_GUID
		if err := binary.Read(rdr, binary.LittleEndian, &guid); err != nil {
			break
		}
		var attributes uint32
		if err := binary.Read(rdr, binary.LittleEndian, &attributes); err != nil {
			break
		}
		var nameSize uint32
		if err := binary.Read(rdr, binary.LittleEndian, &nameSize); err != nil {
			break
		}
		var dataSize uint32
		if err := binary.Read(rdr, binary.LittleEndian, &dataSize); err != nil {
			break
		}

		// Validate size fields.
		if nameSize > 0x1000 || dataSize > maxDataSize {
			log.Printf("Data size is %d for variable at index %d; skipping.", dataSize, startPos)
			skip := int64(nameSize + dataSize)
			if _, err := rdr.Seek(skip, io.SeekCurrent); err != nil {
				break
			}
			continue
		}

		// Read name bytes (UTF-16LE).
		nameBytes := make([]byte, nameSize)
		if _, err := io.ReadFull(rdr, nameBytes); err != nil {
			log.Printf("Failed to read variable name at index %d: %v", startPos, err)
			break
		}
		name, err := decodeUTF16LE(nameBytes)
		if err != nil {
			name = ""
		}

		// Read data.
		if dataSize > uint32(rdr.Len()) {
			log.Printf("Not enough bytes to read data for variable '%s': expected %d, available %d", name, dataSize, rdr.Len())
			break
		}
		data := make([]byte, dataSize)
		if _, err := io.ReadFull(rdr, data); err != nil {
			log.Printf("Failed to read data for variable '%s': %v", name, err)
			break
		}

		val, _ := interpretData(data)
		variable := EFIVariable{
			VendorGUID: guid,
			Name:       name,
			Attributes: attributes,
			Value:      val,
			Data:       data,
		}
		// Only accept variables with non-empty names.
		if strings.TrimSpace(variable.Name) != "" {
			vars = append(vars, variable)
			log.Printf("Parsed Variable: %s", variable.Name)
		}
	}
	return vars, nil
}

func decodeUTF16LE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Remove trailing null if present.
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	s := string(utf16.Decode(u16))
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s, nil
}

func interpretData(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	if len(data)%2 == 0 {
		var runes []uint16
		for i := 0; i < len(data); i += 2 {
			runes = append(runes, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		s := string(utf16.Decode(runes))
		if strings.TrimSpace(s) != "" {
			return s, nil
		}
	}
	if utf8.Valid(data) {
		s := string(data)
		if strings.TrimSpace(s) != "" {
			return s, nil
		}
	}
	return fmt.Sprintf("%x", data), nil
}
