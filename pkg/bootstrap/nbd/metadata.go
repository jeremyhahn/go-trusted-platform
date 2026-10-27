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

package nbd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"strings"
	"unicode/utf16"
)

// The metadata area is partition 1 of a diskless-nbd node's export: the GPT
// partition, FAT32-formatted, that the installer writes the node's UKI and
// its sealed key material to (docs/installer/engineering.md, "The NBD
// metadata area"). The boot server reads the installed UKI out of it, read
// only and without mounting the volume. Nothing read here is trusted beyond
// the bytes served: the firmware verifies the UKI's signature.

const (
	gptSignature       = "EFI PART"
	gptHeaderMinSize   = 92
	gptEntryMinSize    = 128
	gptMaxEntriesBytes = 1 << 20

	fatBootSectorSize = 512
	fatDirEntrySize   = 32
	fatAttrLongName   = 0x0F
	fatAttrVolumeID   = 0x08
	fatAttrDirectory  = 0x10
	fatEntryFree      = 0xE5
	fatLastLongEntry  = 0x40
	fatClusterMask    = 0x0FFFFFFF
	fatEndOfChain     = 0x0FFFFFF8
	fatFirstCluster   = 2
	fatMaxTableBytes  = 16 << 20
	fatMaxDirBytes    = 1 << 20
)

// sectorSizes are the logical sector sizes the export may have been
// partitioned with. The server advertises a 1-byte minimum block size, so the
// client's kernel chose one; the GPT header, always at LBA 1, shows which.
var sectorSizes = []int64{512, 1024, 2048, 4096}

// MetadataFile is a file read out of an installed volume's metadata area.
type MetadataFile struct {
	io.Reader
	// Size is the file's length in bytes.
	Size int64

	volume *os.File
}

// Close releases the volume the file is read from.
func (f *MetadataFile) Close() error {
	return f.volume.Close()
}

// OpenMetadataFile opens name, a slash-separated path matched without regard
// to case as FAT does, in the metadata area of identity's volume, which it
// attaches through volumes as the export server does. A volume that does not exist, or holds no partition table, is
// ErrNotInstalled; one that is partitioned but does not hold name in a
// readable metadata area is ErrMetadataArea.
func OpenMetadataFile(volumes VolumeProvider, identity, name string) (*MetadataFile, error) {
	path, err := volumes.Attach(identity)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInstalled{Identity: identity}
	}
	if err != nil {
		return nil, err
	}
	volume, err := os.Open(path)
	if err != nil {
		return nil, ErrVolume{Identity: identity, Op: "open", Cause: err}
	}
	size, err := volumeSize(identity, volume)
	if err != nil {
		return nil, closeAfter(identity, volume, err)
	}

	area := &metadataReader{identity: identity, volume: volume, size: size}
	reader, size, err := area.open(name)
	if err != nil {
		return nil, closeAfter(identity, volume, err)
	}
	return &MetadataFile{Reader: reader, Size: size, volume: volume}, nil
}

// metadataReader reads one volume's metadata area.
type metadataReader struct {
	identity string
	volume   io.ReaderAt
	size     int64
}

func (m *metadataReader) fail(reason string, cause error) error {
	return ErrMetadataArea{Identity: m.identity, Reason: reason, Cause: cause}
}

// readAt fills buf from the volume at off, refusing a range past its end.
func (m *metadataReader) readAt(buf []byte, off int64, what string) error {
	if off < 0 || off > m.size || int64(len(buf)) > m.size-off {
		return m.fail(what+" lies outside the volume", nil)
	}
	if _, err := m.volume.ReadAt(buf, off); err != nil {
		return m.fail("reading "+what, err)
	}
	return nil
}

func (m *metadataReader) open(name string) (io.Reader, int64, error) {
	offset, length, err := m.partitionOne()
	if err != nil {
		return nil, 0, err
	}
	fat, err := m.openFAT32(offset, length)
	if err != nil {
		return nil, 0, err
	}
	entry, err := fat.open(name)
	if err != nil {
		return nil, 0, err
	}
	reader, err := fat.fileReader(entry)
	if err != nil {
		return nil, 0, err
	}
	return reader, int64(entry.size), nil
}

// gptHeader finds the GPT header and the sector size it was written with. A
// volume with no GPT is not installed, unless it carries an MBR: a partitioned
// volume is never taken for a blank one.
func (m *metadataReader) gptHeader() (int64, []byte, error) {
	for _, sectorSize := range sectorSizes {
		if m.size < 2*sectorSize {
			break
		}
		header := make([]byte, sectorSize)
		if err := m.readAt(header, sectorSize, "GPT header"); err != nil {
			return 0, nil, err
		}
		if string(header[:len(gptSignature)]) == gptSignature {
			return sectorSize, header, nil
		}
	}
	if m.size >= fatBootSectorSize {
		mbr := make([]byte, fatBootSectorSize)
		if err := m.readAt(mbr, 0, "MBR"); err != nil {
			return 0, nil, err
		}
		if mbr[510] == 0x55 && mbr[511] == 0xAA {
			return 0, nil, m.fail("partitioned, but not GPT", nil)
		}
	}
	return 0, nil, ErrNotInstalled{Identity: m.identity}
}

// partitionOne returns the byte range of GPT partition 1, after verifying the
// header's and the entry array's checksums.
func (m *metadataReader) partitionOne() (int64, int64, error) {
	sectorSize, header, err := m.gptHeader()
	if err != nil {
		return 0, 0, err
	}
	headerSize := binary.LittleEndian.Uint32(header[12:16])
	if headerSize < gptHeaderMinSize || int64(headerSize) > sectorSize {
		return 0, 0, m.fail(fmt.Sprintf("GPT header size %d is invalid", headerSize), nil)
	}
	checked := bytes.Clone(header[:headerSize])
	clear(checked[16:20])
	if crc32.ChecksumIEEE(checked) != binary.LittleEndian.Uint32(header[16:20]) {
		return 0, 0, m.fail("GPT header checksum mismatch", nil)
	}

	sectors := uint64(m.size / sectorSize)
	entriesLBA := binary.LittleEndian.Uint64(header[72:80])
	count := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])
	if count == 0 || entrySize < gptEntryMinSize || entrySize%8 != 0 ||
		uint64(count)*uint64(entrySize) > gptMaxEntriesBytes || entriesLBA >= sectors {
		return 0, 0, m.fail("GPT partition entry array is malformed", nil)
	}
	entries := make([]byte, uint64(count)*uint64(entrySize))
	if err := m.readAt(entries, int64(entriesLBA)*sectorSize, "GPT partition entries"); err != nil {
		return 0, 0, err
	}
	if crc32.ChecksumIEEE(entries) != binary.LittleEndian.Uint32(header[88:92]) {
		return 0, 0, m.fail("GPT partition entry checksum mismatch", nil)
	}

	entry := entries[:entrySize]
	if bytes.Equal(entry[:16], make([]byte, 16)) {
		return 0, 0, m.fail("GPT partition 1 is empty", nil)
	}
	first := binary.LittleEndian.Uint64(entry[32:40])
	last := binary.LittleEndian.Uint64(entry[40:48])
	if first == 0 || last < first || last >= sectors {
		return 0, 0, m.fail("GPT partition 1 lies outside the volume", nil)
	}
	return int64(first) * sectorSize, int64(last-first+1) * sectorSize, nil
}

// fat32 is a read-only FAT32 file system within the volume.
type fat32 struct {
	area         *metadataReader
	clusterSize  int64
	dataOffset   int64
	clusterCount uint32
	rootCluster  uint32
	table        []byte
}

// openFAT32 reads the boot sector and the first FAT of the file system at
// offset, which must fit in length bytes.
func (m *metadataReader) openFAT32(offset, length int64) (*fat32, error) {
	boot := make([]byte, fatBootSectorSize)
	if err := m.readAt(boot, offset, "FAT boot sector"); err != nil {
		return nil, err
	}
	le16 := func(at int) uint64 { return uint64(binary.LittleEndian.Uint16(boot[at:])) }
	le32 := func(at int) uint64 { return uint64(binary.LittleEndian.Uint32(boot[at:])) }
	bytesPerSector := le16(11)
	sectorsPerCluster := uint64(boot[13])
	reserved := le16(14)
	fats := uint64(boot[16])
	totalSectors := le16(19)
	if totalSectors == 0 {
		totalSectors = le32(32)
	}
	fatSectors := le32(36)

	switch {
	case boot[510] != 0x55 || boot[511] != 0xAA:
		return nil, m.fail("GPT partition 1 holds no FAT file system", nil)
	case bytesPerSector < 512 || bytesPerSector > 4096 || bytesPerSector&(bytesPerSector-1) != 0,
		sectorsPerCluster == 0 || sectorsPerCluster&(sectorsPerCluster-1) != 0,
		reserved == 0, fats == 0:
		return nil, m.fail("FAT boot sector is malformed", nil)
	case le16(17) != 0 || le16(22) != 0 || fatSectors == 0:
		return nil, m.fail("GPT partition 1 is not FAT32", nil)
	}
	metaSectors := reserved + fats*fatSectors
	if totalSectors*bytesPerSector > uint64(length) || metaSectors >= totalSectors {
		return nil, m.fail("FAT file system does not fit GPT partition 1", nil)
	}
	clusterCount := (totalSectors - metaSectors) / sectorsPerCluster
	tableBytes := fatSectors * bytesPerSector
	if tableBytes > fatMaxTableBytes || (clusterCount+fatFirstCluster)*4 > tableBytes {
		return nil, m.fail(fmt.Sprintf("FAT of %d bytes for %d clusters is malformed", tableBytes, clusterCount), nil)
	}
	table := make([]byte, tableBytes)
	if err := m.readAt(table, offset+int64(reserved*bytesPerSector), "FAT"); err != nil {
		return nil, err
	}

	fat := &fat32{
		area:         m,
		clusterSize:  int64(sectorsPerCluster * bytesPerSector),
		dataOffset:   offset + int64(metaSectors*bytesPerSector),
		clusterCount: uint32(clusterCount),
		rootCluster:  uint32(le32(44) & fatClusterMask),
		table:        table,
	}
	if !fat.inRange(fat.rootCluster) {
		return nil, m.fail("FAT root directory cluster is out of range", nil)
	}
	return fat, nil
}

func (f *fat32) inRange(cluster uint32) bool {
	return cluster >= fatFirstCluster && uint64(cluster) < uint64(f.clusterCount)+fatFirstCluster
}

func (f *fat32) clusterOffset(cluster uint32) int64 {
	return f.dataOffset + int64(cluster-fatFirstCluster)*f.clusterSize
}

// chain follows the cluster chain from first. It refuses a link to a free,
// bad or out-of-range cluster, and a chain longer than the file system has
// clusters, which can only be a loop.
func (f *fat32) chain(first uint32) ([]uint32, error) {
	var clusters []uint32
	for cluster := first; ; {
		if !f.inRange(cluster) {
			return nil, f.area.fail(fmt.Sprintf("cluster chain from %d reaches invalid cluster %#x", first, cluster), nil)
		}
		if uint32(len(clusters)) >= f.clusterCount {
			return nil, f.area.fail(fmt.Sprintf("cluster chain from %d loops", first), nil)
		}
		clusters = append(clusters, cluster)
		next := binary.LittleEndian.Uint32(f.table[cluster*4:]) & fatClusterMask
		if next >= fatEndOfChain {
			return clusters, nil
		}
		cluster = next
	}
}

// fatEntry is a directory entry, named by its long name when it has a valid
// one and by its 8.3 name otherwise.
type fatEntry struct {
	name    string
	dir     bool
	cluster uint32
	size    uint32
}

// open walks name from the root directory to a file.
func (f *fat32) open(name string) (fatEntry, error) {
	parts := strings.Split(strings.Trim(name, "/"), "/")
	cluster := f.rootCluster
	for i, part := range parts {
		path := strings.Join(parts[:i+1], "/")
		entry, found, err := f.lookup(cluster, part)
		if err != nil {
			return fatEntry{}, err
		}
		last := i == len(parts)-1
		switch {
		case !found:
			return fatEntry{}, f.area.fail(path+" not found", fs.ErrNotExist)
		case last && entry.dir:
			return fatEntry{}, f.area.fail(path+" is a directory", nil)
		case last:
			return entry, nil
		case !entry.dir:
			return fatEntry{}, f.area.fail(path+" is not a directory", nil)
		}
		cluster = entry.cluster
	}
	return fatEntry{}, f.area.fail("empty path", nil)
}

// lookup finds name in the directory at cluster, without regard to case.
func (f *fat32) lookup(cluster uint32, name string) (fatEntry, bool, error) {
	clusters, err := f.chain(cluster)
	if err != nil {
		return fatEntry{}, false, err
	}
	if int64(len(clusters))*f.clusterSize > fatMaxDirBytes {
		return fatEntry{}, false, f.area.fail(fmt.Sprintf("directory at cluster %d is larger than %d bytes", cluster, fatMaxDirBytes), nil)
	}
	dir := make([]byte, int64(len(clusters))*f.clusterSize)
	for i, c := range clusters {
		start := int64(i) * f.clusterSize
		if err := f.area.readAt(dir[start:start+f.clusterSize], f.clusterOffset(c), "directory"); err != nil {
			return fatEntry{}, false, err
		}
	}
	for _, entry := range parseDir(dir) {
		if strings.EqualFold(entry.name, name) {
			return entry, true, nil
		}
	}
	return fatEntry{}, false, nil
}

// parseDir decodes a FAT directory's entries. A run of long-name entries
// names the short entry after it only when its checksum matches that entry's
// 8.3 name.
func parseDir(dir []byte) []fatEntry {
	var entries []fatEntry
	var long []uint16
	var longSum byte
	longValid := false
	for off := 0; off+fatDirEntrySize <= len(dir); off += fatDirEntrySize {
		raw := dir[off : off+fatDirEntrySize]
		attr := raw[11]
		switch {
		case raw[0] == 0x00:
			return entries
		case raw[0] == fatEntryFree:
			longValid = false
		case attr&0x3F == fatAttrLongName:
			if raw[0]&fatLastLongEntry != 0 {
				long, longSum, longValid = nil, raw[13], true
			}
			if !longValid || raw[13] != longSum {
				longValid = false
				continue
			}
			long = append(longNameChars(raw), long...)
		case attr&fatAttrVolumeID != 0:
			longValid = false
		default:
			name := shortName(raw[:11])
			if longValid && shortNameChecksum(raw[:11]) == longSum {
				name = decodeLongName(long)
			}
			entries = append(entries, fatEntry{
				name:    name,
				dir:     attr&fatAttrDirectory != 0,
				cluster: uint32(binary.LittleEndian.Uint16(raw[20:22]))<<16 | uint32(binary.LittleEndian.Uint16(raw[26:28])),
				size:    binary.LittleEndian.Uint32(raw[28:32]),
			})
			longValid = false
		}
	}
	return entries
}

// longNameChars are the 13 UTF-16 code units of one long-name entry.
func longNameChars(raw []byte) []uint16 {
	var chars []uint16
	for _, span := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for at := span[0]; at < span[1]; at += 2 {
			chars = append(chars, binary.LittleEndian.Uint16(raw[at:]))
		}
	}
	return chars
}

// decodeLongName ends a long name at its NUL; the 0xFFFF padding follows it.
func decodeLongName(chars []uint16) string {
	for i, c := range chars {
		if c == 0 {
			chars = chars[:i]
			break
		}
	}
	return string(utf16.Decode(chars))
}

func shortName(raw []byte) string {
	base := strings.TrimRight(string(raw[:8]), " ")
	ext := strings.TrimRight(string(raw[8:11]), " ")
	if ext == "" {
		return base
	}
	return base + "." + ext
}

func shortNameChecksum(raw []byte) byte {
	var sum byte
	for _, c := range raw {
		sum = (sum>>1 | sum<<7) + c
	}
	return sum
}

// fileReader reads entry's data, after checking its chain holds all of it.
func (f *fat32) fileReader(entry fatEntry) (io.Reader, error) {
	if entry.size == 0 {
		return bytes.NewReader(nil), nil
	}
	clusters, err := f.chain(entry.cluster)
	if err != nil {
		return nil, err
	}
	needed := (int64(entry.size) + f.clusterSize - 1) / f.clusterSize
	if int64(len(clusters)) < needed {
		return nil, f.area.fail(fmt.Sprintf("%s: %d bytes need %d clusters, its chain has %d",
			entry.name, entry.size, needed, len(clusters)), nil)
	}
	return &clusterReader{fat: f, clusters: clusters[:needed], remaining: int64(entry.size)}, nil
}

// clusterReader streams a file cluster by cluster.
type clusterReader struct {
	fat       *fat32
	clusters  []uint32
	offset    int64
	remaining int64
}

func (r *clusterReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if r.offset == r.fat.clusterSize {
		r.clusters, r.offset = r.clusters[1:], 0
	}
	n := min(int64(len(p)), r.fat.clusterSize-r.offset, r.remaining)
	if err := r.fat.area.readAt(p[:n], r.fat.clusterOffset(r.clusters[0])+r.offset, "file data"); err != nil {
		return 0, err
	}
	r.offset += n
	r.remaining -= n
	return int(n), nil
}
