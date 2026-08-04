// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package uefi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unicode/utf16"
)

// NVRAM represents an OVMF NVRAM variable store
type NVRAM struct {
	path          string
	data          []byte
	fvHeader      *FirmwareVolumeHeader
	fvHeaderLen   int
	varStoreStart int
	varStoreEnd   int
	// authStore reports whether the variable store uses the AUTHENTICATED
	// variable format (store signature gEfiAuthenticatedVariableGuid). In an
	// authenticated store EVERY variable carries the 60-byte
	// AUTHENTICATED_VARIABLE_HEADER regardless of its attributes — the header
	// layout is a property of the STORE, not of the individual variable.
	// Choosing the header size per-variable (e.g. from the TIME_BASED_AUTH
	// attribute bit) writes a store that firmware cannot walk.
	authStore bool
	variables []*variableEntry
}

// variableEntry represents a parsed variable with its location in the store
type variableEntry struct {
	offset    int
	headerLen int
	variable  *Variable
	state     uint8
	isAuth    bool
	rawHeader []byte
}

// OpenNVRAM opens and parses an OVMF NVRAM file
func OpenNVRAM(path string) (*NVRAM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to read NVRAM file", Err: err}
	}

	return ParseNVRAM(data, path)
}

// ParseNVRAM parses NVRAM data from a byte slice
func ParseNVRAM(data []byte, path string) (*NVRAM, error) {
	nvram := &NVRAM{
		path: path,
		data: data,
	}

	if err := nvram.parse(); err != nil {
		return nil, err
	}

	return nvram, nil
}

// parse parses the NVRAM structure
func (n *NVRAM) parse() error {
	// Parse firmware volume header
	if err := n.parseFirmwareVolumeHeader(); err != nil {
		return &WrappedError{Msg: "failed to parse firmware volume header", Err: err}
	}

	// Find and parse variable store
	if err := n.parseVariableStore(); err != nil {
		return &WrappedError{Msg: "failed to parse variable store", Err: err}
	}

	// Parse variables
	if err := n.parseVariables(); err != nil {
		return &WrappedError{Msg: "failed to parse variables", Err: err}
	}

	return nil
}

// parseFirmwareVolumeHeader parses the FV header at the beginning of the file
func (n *NVRAM) parseFirmwareVolumeHeader() error {
	if len(n.data) < FirmwareVolumeHeaderMinSize {
		return &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "file too small for firmware volume header"}}
	}

	n.fvHeader = &FirmwareVolumeHeader{}

	// Copy zero vector
	copy(n.fvHeader.ZeroVector[:], n.data[0:16])

	// Parse FileSystem GUID
	var err error
	n.fvHeader.FileSystemGUID, err = GUIDFromBytes(n.data[16:32])
	if err != nil {
		return &WrappedError{Msg: "failed to parse filesystem GUID", Err: err}
	}

	// Parse remaining fields
	n.fvHeader.FvLength = binary.LittleEndian.Uint64(n.data[32:40])
	copy(n.fvHeader.Signature[:], n.data[40:44])
	n.fvHeader.Attributes = binary.LittleEndian.Uint32(n.data[44:48])
	n.fvHeader.HeaderLength = binary.LittleEndian.Uint16(n.data[48:50])
	n.fvHeader.Checksum = binary.LittleEndian.Uint16(n.data[50:52])
	n.fvHeader.ExtHeaderOffset = binary.LittleEndian.Uint16(n.data[52:54])
	n.fvHeader.Reserved = n.data[54]
	n.fvHeader.Revision = n.data[55]

	// Validate signature
	if n.fvHeader.Signature != FirmwareVolumeSignature {
		return &SentinelCauseError{Sentinel: ErrInvalidSignature, Cause: &MessageError{Msg: fmt.Sprintf("expected '_FVH', got '%s'", string(n.fvHeader.Signature[:]))}}
	}

	n.fvHeaderLen = int(n.fvHeader.HeaderLength)

	return nil
}

// parseVariableStore finds and parses the variable store header
func (n *NVRAM) parseVariableStore() error {
	// Variable store typically starts right after FV header
	// Look for the variable store signature GUID
	offset := n.fvHeaderLen

	// In OVMF, the variable store header follows the FV header
	if offset+VariableStoreHeaderSize > len(n.data) {
		return &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "file too small for variable store header"}}
	}

	// Parse variable store header
	vsGUID, err := GUIDFromBytes(n.data[offset : offset+GUIDSize])
	if err != nil {
		return &WrappedError{Msg: "failed to parse variable store GUID", Err: err}
	}

	// Check for known variable store GUIDs
	// OVMF uses either the standard or authenticated variable format
	if !vsGUID.Equal(NVRAMVariableStoreGUID) && !vsGUID.Equal(AuthenticatedVariableGUID) {
		// Try to find it by scanning
		found := false
		for i := n.fvHeaderLen; i < len(n.data)-VariableStoreHeaderSize; i++ {
			testGUID, _ := GUIDFromBytes(n.data[i : i+GUIDSize])
			if testGUID.Equal(NVRAMVariableStoreGUID) || testGUID.Equal(AuthenticatedVariableGUID) {
				offset = i
				vsGUID = testGUID
				found = true
				break
			}
		}
		if !found {
			// Variable store not found, but file might still be valid NVRAM
			// with variables starting after FV header
			n.varStoreStart = n.fvHeaderLen + VariableStoreHeaderSize
			n.varStoreEnd = len(n.data)
			return nil
		}
	}

	n.authStore = vsGUID.Equal(AuthenticatedVariableGUID)

	vsSize := binary.LittleEndian.Uint32(n.data[offset+GUIDSize : offset+GUIDSize+4])

	n.varStoreStart = offset + VariableStoreHeaderSize
	n.varStoreEnd = offset + int(vsSize)

	if n.varStoreEnd > len(n.data) {
		n.varStoreEnd = len(n.data)
	}

	return nil
}

// parseVariables parses all variables in the variable store
func (n *NVRAM) parseVariables() error {
	n.variables = make([]*variableEntry, 0)
	offset := n.varStoreStart

	for offset < n.varStoreEnd-VariableHeaderSize {
		// Check for start ID (0x55AA)
		startID := binary.LittleEndian.Uint16(n.data[offset : offset+2])
		if startID != VariableHeaderStartID {
			// End of variables or invalid - scan for next valid variable
			offset++
			continue
		}

		entry, nextOffset, err := n.parseVariable(offset)
		if err != nil {
			// Try to continue with next position
			offset++
			continue
		}

		if entry != nil && entry.state == VarStateAdded {
			n.variables = append(n.variables, entry)
		}

		offset = nextOffset
	}

	return nil
}

// parseVariable parses a single variable at the given offset
func (n *NVRAM) parseVariable(offset int) (*variableEntry, int, error) {
	if offset+VariableHeaderSize > len(n.data) {
		return nil, offset + 1, &MessageError{Msg: "insufficient data for variable header"}
	}

	state := n.data[offset+2]

	// Read attributes to check for authenticated write
	attrs := binary.LittleEndian.Uint32(n.data[offset+4 : offset+8])

	// The header layout is a property of the STORE, not of the variable's
	// attributes: an authenticated store uses the 60-byte header for every
	// variable it holds.
	isAuth := n.authStore

	var nameSize, dataSize uint32
	var vendorGUID GUID
	var headerLen int
	var err error

	if isAuth {
		// Authenticated variable header (60 bytes)
		if offset+AuthVariableHeaderSize > len(n.data) {
			return nil, offset + 1, &MessageError{Msg: "insufficient data for auth variable header"}
		}

		// Skip StartID(2), State(1), Reserved(1), Attributes(4), MonotonicCount(8), Timestamp(16), PubKeyIndex(4)
		// = 36 bytes before NameSize
		nameSize = binary.LittleEndian.Uint32(n.data[offset+36 : offset+40])
		dataSize = binary.LittleEndian.Uint32(n.data[offset+40 : offset+44])
		vendorGUID, err = GUIDFromBytes(n.data[offset+44 : offset+60])
		if err != nil {
			return nil, offset + 1, &WrappedError{Msg: "failed to parse vendor GUID", Err: err}
		}
		headerLen = AuthVariableHeaderSize
	} else {
		// Standard variable header (32 bytes)
		// Skip StartID(2), State(1), Reserved(1), Attributes(4)
		// = 8 bytes before NameSize
		nameSize = binary.LittleEndian.Uint32(n.data[offset+8 : offset+12])
		dataSize = binary.LittleEndian.Uint32(n.data[offset+12 : offset+16])
		vendorGUID, err = GUIDFromBytes(n.data[offset+16 : offset+32])
		if err != nil {
			return nil, offset + 1, &WrappedError{Msg: "failed to parse vendor GUID", Err: err}
		}
		headerLen = VariableHeaderSize
	}

	// Sanity check sizes
	if nameSize > 1024*1024 || dataSize > 64*1024*1024 {
		return nil, offset + 1, &MessageError{Msg: "variable size out of bounds"}
	}

	totalSize := headerLen + int(nameSize) + int(dataSize)
	if offset+totalSize > len(n.data) {
		return nil, offset + 1, &MessageError{Msg: "variable data extends beyond buffer"}
	}

	// Parse name (UTF-16LE, null-terminated)
	nameBytes := n.data[offset+headerLen : offset+headerLen+int(nameSize)]
	name := decodeUTF16LE(nameBytes)

	// Parse data
	data := make([]byte, dataSize)
	copy(data, n.data[offset+headerLen+int(nameSize):offset+headerLen+int(nameSize)+int(dataSize)])

	entry := &variableEntry{
		offset:    offset,
		headerLen: headerLen,
		state:     state,
		isAuth:    isAuth,
		rawHeader: make([]byte, headerLen),
		variable: &Variable{
			Name:       name,
			GUID:       vendorGUID,
			Attributes: attrs,
			Data:       data,
		},
	}
	copy(entry.rawHeader, n.data[offset:offset+headerLen])

	// Align to 4-byte boundary
	nextOffset := offset + totalSize
	if nextOffset%4 != 0 {
		nextOffset += 4 - (nextOffset % 4)
	}

	return entry, nextOffset, nil
}

// decodeUTF16LE decodes a UTF-16LE encoded string, stopping at null terminator
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Convert to uint16 slice
	u16 := make([]uint16, len(data)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
	}

	// Find null terminator
	for i, v := range u16 {
		if v == 0 {
			u16 = u16[:i]
			break
		}
	}

	return string(utf16.Decode(u16))
}

// encodeUTF16LE encodes a string as UTF-16LE with null terminator
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)

	// Add null terminator
	u16 = append(u16, 0)

	data := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(data[i*2:], v)
	}

	return data
}

// GetVariable retrieves a variable by name and GUID
func (n *NVRAM) GetVariable(name string, guid GUID) (*Variable, error) {
	for _, entry := range n.variables {
		if entry.variable.Name == name && entry.variable.GUID.Equal(guid) {
			return entry.variable, nil
		}
	}
	return nil, ErrVariableNotFound
}

// ListVariables returns all variables in the store
func (n *NVRAM) ListVariables() []*Variable {
	vars := make([]*Variable, len(n.variables))
	for i, entry := range n.variables {
		vars[i] = entry.variable
	}
	return vars
}

// SetVariable sets or updates a variable in the store
// For Secure Boot variables, the data should be an EFI_SIGNATURE_LIST
func (n *NVRAM) SetVariable(name string, guid GUID, attrs uint32, data []byte) error {
	// Find existing variable
	for i, entry := range n.variables {
		if entry.variable.Name == name && entry.variable.GUID.Equal(guid) {
			// Update existing variable
			entry.variable.Data = data
			entry.variable.Attributes = attrs
			entry.isAuth = n.authStore
			n.variables[i] = entry
			return nil
		}
	}

	// Create new variable
	newVar := &Variable{
		Name:       name,
		GUID:       guid,
		Attributes: attrs,
		Data:       data,
	}

	entry := &variableEntry{
		offset:   -1, // Will be set on save
		state:    VarStateAdded,
		isAuth:   n.authStore,
		variable: newVar,
	}

	n.variables = append(n.variables, entry)
	return nil
}

// DeleteVariable marks a variable as deleted
func (n *NVRAM) DeleteVariable(name string, guid GUID) error {
	for i, entry := range n.variables {
		if entry.variable.Name == name && entry.variable.GUID.Equal(guid) {
			// Remove from slice
			n.variables = append(n.variables[:i], n.variables[i+1:]...)
			return nil
		}
	}
	return ErrVariableNotFound
}

// Save writes the NVRAM back to the file
func (n *NVRAM) Save() error {
	if n.path == "" {
		return &MessageError{Msg: "no file path specified"}
	}

	return n.SaveTo(n.path)
}

// SaveTo writes the NVRAM to a specific file
func (n *NVRAM) SaveTo(path string) error {
	data, err := n.Bytes()
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// Bytes serializes the NVRAM to bytes
func (n *NVRAM) Bytes() ([]byte, error) {
	// Create new buffer with original data
	result := make([]byte, len(n.data))
	copy(result, n.data)

	// Clear variable area and rebuild
	if n.varStoreStart > 0 && n.varStoreEnd > n.varStoreStart {
		// Fill with 0xFF (erased state)
		for i := n.varStoreStart; i < n.varStoreEnd; i++ {
			result[i] = 0xFF
		}
	}

	// Write variables
	offset := n.varStoreStart
	for _, entry := range n.variables {
		varBytes, err := n.serializeVariable(entry.variable, n.authStore)
		if err != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("failed to serialize variable %s", entry.variable.Name), Err: err}
		}

		// Check if fits
		if offset+len(varBytes) > n.varStoreEnd {
			return nil, ErrInsufficientSpace
		}

		copy(result[offset:], varBytes)
		offset += len(varBytes)

		// Align to 4-byte boundary
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	return result, nil
}

// serializeVariable converts a variable to its binary representation
func (n *NVRAM) serializeVariable(v *Variable, isAuth bool) ([]byte, error) {
	nameBytes := encodeUTF16LE(v.Name)
	nameSize := uint32(len(nameBytes))
	dataSize := uint32(len(v.Data))

	var buf bytes.Buffer

	// writeLE writes a value in little-endian format, returning the first error
	var writeErr error
	writeLE := func(data interface{}) {
		if writeErr != nil {
			return
		}
		writeErr = binary.Write(&buf, binary.LittleEndian, data)
	}

	if isAuth {
		// Authenticated variable header
		writeLE(VariableHeaderStartID)
		buf.WriteByte(VarStateAdded)
		buf.WriteByte(0) // Reserved

		writeLE(v.Attributes)
		writeLE(uint64(0)) // MonotonicCount

		// EFI_TIME (16 bytes)
		buf.Write(make([]byte, EFITimeSize))

		writeLE(uint32(0)) // PubKeyIndex
		writeLE(nameSize)
		writeLE(dataSize)
		buf.Write(v.GUID.Bytes())
	} else {
		// Standard variable header
		writeLE(VariableHeaderStartID)
		buf.WriteByte(VarStateAdded)
		buf.WriteByte(0) // Reserved

		writeLE(v.Attributes)
		writeLE(nameSize)
		writeLE(dataSize)
		buf.Write(v.GUID.Bytes())
	}

	if writeErr != nil {
		return nil, writeErr
	}

	// Write name and data
	buf.Write(nameBytes)
	buf.Write(v.Data)

	return buf.Bytes(), nil
}

// WriteTo writes the NVRAM to a writer
func (n *NVRAM) WriteTo(w io.Writer) (int64, error) {
	data, err := n.Bytes()
	if err != nil {
		return 0, err
	}

	written, err := w.Write(data)
	return int64(written), err
}

// IsAuthenticatedStore reports whether the variable store uses the
// authenticated variable format (60-byte variable headers).
func (n *NVRAM) IsAuthenticatedStore() bool {
	return n.authStore
}

// Path returns the file path
func (n *NVRAM) Path() string {
	return n.path
}

// Size returns the total NVRAM size
func (n *NVRAM) Size() int {
	return len(n.data)
}
