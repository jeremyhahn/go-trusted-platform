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

// Package nbdtest builds NBD export volumes for tests, byte by byte, as
// parted and mkfs.vfat lay out a diskless-nbd node's metadata area: a
// protective MBR, a GPT whose partition 1 starts at 1 MiB, and a FAT32 file
// system in it with long names. It writes the formats independently of the
// reader in package nbd, so a test of one checks the other.
package nbdtest

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"
	"unicode/utf16"
)

const (
	// ClusterCount is the number of clusters in a built file system.
	ClusterCount = 256

	// EndOfChain is the FAT link that ends a cluster chain.
	EndOfChain = 0x0FFFFFFF

	firstCluster  = 2
	dirEntrySize  = 32
	reserved      = 32
	gptEntries    = 128
	gptEntrySize  = 128
	gptHeaderSize = 92
	attrArchive   = 0x20
	attrDirectory = 0x10
	attrLongName  = 0x0F
	lastLongEntry = 0x40
	entryDeleted  = 0xE5
)

var espType = []byte{0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}

// Node is a file, or a directory when Children is not nil.
type Node struct {
	Name string
	// Short is the 11-byte, space-padded 8.3 name; a Name it does not spell
	// gets long-name entries too.
	Short    string
	Data     []byte
	Children []Node
}

// Image is a built volume and where its parts are.
type Image struct {
	Bytes           []byte
	SectorSize      int64
	PartitionOffset int64
	FATOffset       int64
	// FirstCluster is each file's and directory's first cluster, by path.
	FirstCluster map[string]uint32
}

// InstalledTree is a metadata area as the installer leaves it: the UKI as
// EFI/BOOT/<bootFile>, and the TPM artifacts under tpm2/.
func InstalledTree(bootFile string, uki []byte) []Node {
	return []Node{
		{Name: "EFI", Short: "EFI        ", Children: []Node{
			{Name: "BOOT", Short: "BOOT       ", Children: []Node{
				{Name: bootFile, Short: ShortName(bootFile), Data: uki},
			}},
		}},
		{Name: "tpm2", Short: "TPM2       ", Children: []Node{
			{Name: "pcr-banks", Short: "PCR-BA~1   ", Data: []byte("sha256\n")},
			{Name: "seal-platform.pub", Short: "SEAL-P~1PUB", Data: []byte("sealed public")},
			{Name: "installer.luks", Short: "INSTAL~1LUK", Data: []byte("sealed luks key")},
			{Name: "empty", Short: "EMPTY      ", Data: []byte{}},
		}},
	}
}

// ShortName is the padded 8.3 form of an upper-case name that has one.
func ShortName(name string) string {
	base, ext, _ := strings.Cut(name, ".")
	return fmt.Sprintf("%-8s%-3s", base, ext)
}

type builder struct {
	t           testing.TB
	clusterSize int
	data        map[uint32][]byte
	table       []uint32
	next        uint32
	first       map[string]uint32
}

// alloc stores content in clusters one apart, so only a reader that follows
// the FAT reads it back.
func (b *builder) alloc(path string, content []byte) uint32 {
	if len(content) == 0 {
		return 0
	}
	count := (len(content) + b.clusterSize - 1) / b.clusterSize
	chain := make([]uint32, count)
	for i := range chain {
		if int(b.next) >= len(b.table) {
			b.t.Fatalf("nbdtest: the tree needs more than %d clusters", ClusterCount)
		}
		chain[i] = b.next
		b.next += 2
	}
	for i, cluster := range chain {
		chunk := make([]byte, b.clusterSize)
		copy(chunk, content[i*b.clusterSize:])
		b.data[cluster] = chunk
		b.table[cluster] = EndOfChain
		if i+1 < len(chain) {
			b.table[cluster] = chain[i+1]
		}
	}
	b.first[path] = chain[0]
	return chain[0]
}

// dir lays out a directory's children, then the directory itself after
// padding deleted entries.
func (b *builder) dir(path string, children []Node, padding int) uint32 {
	var entries []byte
	for range padding {
		deleted := make([]byte, dirEntrySize)
		deleted[0] = entryDeleted
		entries = append(entries, deleted...)
	}
	for _, child := range children {
		childPath := strings.TrimPrefix(path+"/"+child.Name, "/")
		attr := byte(attrArchive)
		size := uint32(len(child.Data))
		var cluster uint32
		if child.Children != nil {
			attr, size = attrDirectory, 0
			cluster = b.dir(childPath, child.Children, 0)
		} else {
			cluster = b.alloc(childPath, child.Data)
		}
		if ShortName(child.Name) != child.Short {
			entries = append(entries, LongNameEntries(child.Name, child.Short)...)
		}
		entries = append(entries, DirEntry(child.Short, attr, cluster, size)...)
	}
	return b.alloc(path, append(entries, make([]byte, dirEntrySize)...))
}

// DirEntry is a FAT 8.3 directory entry.
func DirEntry(short string, attr byte, cluster, size uint32) []byte {
	raw := make([]byte, dirEntrySize)
	copy(raw, short)
	raw[11] = attr
	binary.LittleEndian.PutUint16(raw[20:], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(raw[26:], uint16(cluster))
	binary.LittleEndian.PutUint32(raw[28:], size)
	return raw
}

// LongNameEntries are name's long-name entries, in on-disk order (the last
// part first), carrying the checksum of the 8.3 name short.
func LongNameEntries(name, short string) []byte {
	var sum byte
	for _, c := range []byte(short) {
		sum = (sum>>1 | sum<<7) + c
	}
	units := utf16.Encode([]rune(name))
	if len(units)%13 != 0 {
		units = append(units, 0)
	}
	for len(units)%13 != 0 {
		units = append(units, 0xFFFF)
	}
	parts := len(units) / 13
	var out []byte
	for seq := parts; seq >= 1; seq-- {
		raw := make([]byte, dirEntrySize)
		raw[0] = byte(seq)
		if seq == parts {
			raw[0] |= lastLongEntry
		}
		raw[11] = attrLongName
		raw[13] = sum
		chars := units[(seq-1)*13 : seq*13]
		at := 0
		for _, span := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
			for off := span[0]; off < span[1]; off += 2 {
				binary.LittleEndian.PutUint16(raw[off:], chars[at])
				at++
			}
		}
		out = append(out, raw...)
	}
	return out
}

// BuildImage builds a GPT volume of sectorSize-byte sectors whose partition 1
// is a FAT32 file system holding root, with a cluster per sector. The root
// directory spans more than one cluster.
func BuildImage(t testing.TB, sectorSize int64, root []Node) Image {
	t.Helper()
	ss := int(sectorSize)
	b := &builder{
		t:           t,
		clusterSize: ss,
		data:        map[uint32][]byte{},
		table:       make([]uint32, ClusterCount+firstCluster),
		next:        firstCluster,
		first:       map[string]uint32{},
	}
	b.table[0], b.table[1] = 0x0FFFFFF8, EndOfChain
	rootCluster := b.dir("", root, ss/dirEntrySize)

	fatSectors := ((ClusterCount+firstCluster)*4 + ss - 1) / ss
	totalSectors := reserved + 2*fatSectors + ClusterCount
	partLBA := (1 << 20) / ss
	partOffset := partLBA * ss
	img := make([]byte, partOffset+totalSectors*ss+33*ss)

	// Protective MBR.
	img[446+4] = 0xEE
	img[510], img[511] = 0x55, 0xAA

	// FAT32 boot sector.
	boot := img[partOffset:]
	boot[0], boot[1], boot[2] = 0xEB, 0x58, 0x90
	copy(boot[3:], "mkfs.fat")
	binary.LittleEndian.PutUint16(boot[11:], uint16(ss))
	boot[13] = 1
	binary.LittleEndian.PutUint16(boot[14:], reserved)
	boot[16] = 2
	boot[21] = 0xF8
	binary.LittleEndian.PutUint32(boot[32:], uint32(totalSectors))
	binary.LittleEndian.PutUint32(boot[36:], uint32(fatSectors))
	binary.LittleEndian.PutUint32(boot[44:], rootCluster)
	copy(boot[71:], "EFI        FAT32   ")
	boot[510], boot[511] = 0x55, 0xAA

	fatOffset := partOffset + reserved*ss
	for copyIndex := range 2 {
		table := img[fatOffset+copyIndex*fatSectors*ss:]
		for cluster, link := range b.table {
			binary.LittleEndian.PutUint32(table[cluster*4:], link)
		}
	}
	dataOffset := fatOffset + 2*fatSectors*ss
	for cluster, chunk := range b.data {
		copy(img[dataOffset+int(cluster-firstCluster)*ss:], chunk)
	}

	// GPT: the header at LBA 1, the entry array from LBA 2.
	header := img[ss:]
	copy(header, "EFI PART")
	binary.LittleEndian.PutUint32(header[8:], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:], gptHeaderSize)
	binary.LittleEndian.PutUint64(header[24:], 1)
	binary.LittleEndian.PutUint64(header[32:], uint64(len(img)/ss-1))
	binary.LittleEndian.PutUint64(header[72:], 2)
	binary.LittleEndian.PutUint32(header[80:], gptEntries)
	binary.LittleEndian.PutUint32(header[84:], gptEntrySize)
	entry := img[2*ss:]
	copy(entry, espType)
	copy(entry[16:], "unique-guid-0001")
	binary.LittleEndian.PutUint64(entry[32:], uint64(partLBA))
	binary.LittleEndian.PutUint64(entry[40:], uint64(partLBA+totalSectors-1))

	image := Image{
		Bytes:           img,
		SectorSize:      sectorSize,
		PartitionOffset: int64(partOffset),
		FATOffset:       int64(fatOffset),
		FirstCluster:    b.first,
	}
	image.ResealGPT()
	return image
}

// ResealGPT recomputes the GPT checksums, for a test that edits an entry.
func (img Image) ResealGPT() {
	header := img.Bytes[img.SectorSize : img.SectorSize+gptHeaderSize]
	entries := img.Bytes[2*img.SectorSize : 2*img.SectorSize+gptEntries*gptEntrySize]
	binary.LittleEndian.PutUint32(header[88:], crc32.ChecksumIEEE(entries))
	clear(header[16:20])
	binary.LittleEndian.PutUint32(header[16:], crc32.ChecksumIEEE(header))
}

// SetLink points cluster's entry in the first FAT at link.
func (img Image) SetLink(cluster, link uint32) {
	binary.LittleEndian.PutUint32(img.Bytes[img.FATOffset+int64(cluster)*4:], link)
}
