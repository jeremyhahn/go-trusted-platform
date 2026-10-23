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

package fatimage

import (
	"encoding/binary"
	"sort"
	"strings"
	"unicode/utf16"
)

// Image is a FAT16 volume image opened for reading: what a bootloader does to
// the ramdisk it has verified.
type Image struct {
	data        []byte
	spc         int
	fat         []byte
	rootOff     int
	rootEntries int
	dataOff     int
	clusters    int
	label       string
}

// dirent is one decoded directory entry.
type dirent struct {
	name  string
	isDir bool
	first int
	size  int
}

// Open reads the volume's geometry from its boot sector. It accepts the
// 512-byte-sector FAT16 volumes Build writes.
func Open(data []byte) (*Image, error) {
	if len(data) < sectorSize {
		return nil, &FormatError{Reason: "the image is shorter than a boot sector"}
	}
	b := data[:sectorSize]
	if b[510] != 0x55 || b[511] != 0xAA {
		return nil, &FormatError{Reason: "the boot sector has no 55 AA signature"}
	}
	if bps := int(binary.LittleEndian.Uint16(b[11:])); bps != sectorSize {
		return nil, &FormatError{Reason: "sectors are not 512 bytes"}
	}
	spc := int(b[13])
	if spc == 0 || spc&(spc-1) != 0 {
		return nil, &FormatError{Reason: "sectors per cluster is not a power of two"}
	}
	reserved := int(binary.LittleEndian.Uint16(b[14:]))
	fats := int(b[16])
	rootEntries := int(binary.LittleEndian.Uint16(b[17:]))
	fatSectors := int(binary.LittleEndian.Uint16(b[22:]))
	if reserved == 0 || fats == 0 || fatSectors == 0 {
		return nil, &FormatError{Reason: "not a FAT12/16 boot sector (FAT32 volumes are not read)"}
	}
	total := int(binary.LittleEndian.Uint16(b[19:]))
	if total == 0 {
		total = int(binary.LittleEndian.Uint32(b[32:]))
	}
	if total <= 0 {
		return nil, &GeometryError{Field: "total sectors", Reason: "the volume has no sectors"}
	}
	if total*sectorSize > len(data) {
		return nil, &FormatError{Reason: "the image is shorter than its boot sector says"}
	}

	rootSectors := (rootEntries*entrySize + sectorSize - 1) / sectorSize
	fatStart := reserved
	rootStart := reserved + fats*fatSectors
	dataStart := rootStart + rootSectors
	if fatStart >= total || rootStart > total || dataStart > total {
		return nil, &GeometryError{Field: "layout", Reason: "reserved sectors, FATs and root directory exceed the image"}
	}
	clusters := (total - dataStart) / spc
	if clusters < minClusters || clusters > maxClusters {
		return nil, &FormatError{Reason: "the volume has a cluster count that is not FAT16"}
	}
	fatBytes := fatSectors * sectorSize
	if fatBytes < (clusters+2)*2 {
		return nil, &GeometryError{Field: "FAT", Reason: "the FAT is too small for the advertised cluster count"}
	}
	fatOff := fatStart * sectorSize
	fatEnd := fatOff + fatBytes
	rootOff := rootStart * sectorSize
	rootEnd := rootOff + rootEntries*entrySize
	dataOff := dataStart * sectorSize
	if fatEnd > total*sectorSize || rootEnd > total*sectorSize || dataOff > total*sectorSize {
		return nil, &GeometryError{Field: "byte ranges", Reason: "a FAT region points outside the image"}
	}
	return &Image{
		data:        data,
		spc:         spc,
		fat:         data[fatOff:fatEnd],
		rootOff:     rootOff,
		rootEntries: rootEntries,
		dataOff:     dataOff,
		clusters:    clusters,
		label:       strings.TrimRight(string(b[43:54]), " "),
	}, nil
}

// Label is the volume label.
func (i *Image) Label() string { return i.label }

// Files lists every file's path, slash-separated and sorted, as the image
// stores the names.
func (i *Image) Files() ([]string, error) {
	var out []string
	entries := 0
	if err := i.walk("", i.rootBytes(), &out, 0, map[int]bool{}, &entries); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// maxDepth bounds directory recursion, so a corrupt image whose directories
// point at each other cannot loop.
const maxDepth = 16

func (i *Image) walk(prefix string, dir []byte, out *[]string, depth int, seen map[int]bool, entries *int) error {
	if depth > maxDepth {
		return &FormatError{Reason: "directories nest deeper than the reader follows"}
	}
	*entries += len(dir) / entrySize
	if *entries > i.maxEntries() {
		return &FormatError{Reason: "directories contain more entries than the volume can hold"}
	}
	for _, e := range parseDir(dir) {
		p := prefix + e.name
		if !e.isDir {
			*out = append(*out, p)
			continue
		}
		sub, err := i.chain(e.first, 0, seen)
		if err != nil {
			return err
		}
		if err := i.walk(p+"/", sub, out, depth+1, seen, entries); err != nil {
			return err
		}
	}
	return nil
}

// ReadFile returns the contents of the file at p, matching names the way FAT
// does, ignoring case.
func (i *Image) ReadFile(p string) ([]byte, error) {
	dir := i.rootBytes()
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for depth, part := range parts {
		var found *dirent
		for _, e := range parseDir(dir) {
			if strings.EqualFold(e.name, part) {
				found = &e
				break
			}
		}
		if found == nil {
			return nil, &NotFoundError{Path: p}
		}
		last := depth == len(parts)-1
		switch {
		case last && found.isDir, !last && !found.isDir:
			return nil, &NotFoundError{Path: p}
		case last:
			return i.chain(found.first, found.size, nil)
		}
		var err error
		if dir, err = i.chain(found.first, 0, nil); err != nil {
			return nil, err
		}
	}
	return nil, &NotFoundError{Path: p}
}

func (i *Image) rootBytes() []byte {
	return i.data[i.rootOff : i.rootOff+i.rootEntries*entrySize]
}

func (i *Image) maxEntries() int {
	return i.rootEntries + i.clusters*i.spc*sectorSize/entrySize
}

// chain reads the cluster chain starting at first. With size > 0 the result is
// cut to size; with size 0 whole clusters are returned (a directory).
func (i *Image) chain(first, size int, claimed map[int]bool) ([]byte, error) {
	if first == 0 {
		return nil, nil
	}
	cb := i.spc * sectorSize
	var out []byte
	seen := map[int]bool{}
	for c := first; ; {
		if c < 2 || c >= i.clusters+2 {
			return nil, &FormatError{Reason: "a cluster chain leaves the volume"}
		}
		if seen[c] {
			return nil, &FormatError{Reason: "a cluster chain loops"}
		}
		seen[c] = true
		if claimed != nil {
			if claimed[c] {
				return nil, &FormatError{Reason: "a directory cluster is referenced more than once"}
			}
			claimed[c] = true
		}
		if len(seen) > i.clusters {
			return nil, &FormatError{Reason: "a cluster chain is longer than the volume"}
		}
		off := i.dataOff + (c-2)*cb
		if off < 0 || off+cb > len(i.data) {
			return nil, &GeometryError{Field: "cluster", Reason: "a cluster points outside the image"}
		}
		out = append(out, i.data[off:off+cb]...)
		next := int(binary.LittleEndian.Uint16(i.fat[c*2:]))
		if next >= 0xFFF8 {
			break
		}
		c = next
	}
	if size > 0 {
		if size > len(out) {
			return nil, &FormatError{Reason: "a file is larger than its cluster chain"}
		}
		out = out[:size]
	}
	return out, nil
}

// parseDir decodes a directory table, joining VFAT entries to the short entry
// they name.
func parseDir(dir []byte) []dirent {
	var out []dirent
	var parts [][]uint16 // VFAT parts in the order read: last part first
	for off := 0; off+entrySize <= len(dir); off += entrySize {
		e := dir[off : off+entrySize]
		switch {
		case e[0] == 0x00:
			return out
		case e[0] == 0xE5:
			parts = nil
			continue
		case e[11] == attrLFN:
			parts = append(parts, longUnits(e))
			continue
		case e[11]&attrVolume != 0, e[0] == '.':
			parts = nil
			continue
		}
		name := shortString(e[0:11], e[12])
		if len(parts) > 0 {
			var units []uint16
			for p := len(parts) - 1; p >= 0; p-- {
				units = append(units, parts[p]...)
			}
			name = string(utf16.Decode(trimUnits(units)))
		}
		parts = nil
		out = append(out, dirent{
			name:  name,
			isDir: e[11]&attrDirectory != 0,
			first: int(binary.LittleEndian.Uint16(e[26:])),
			size:  int(binary.LittleEndian.Uint32(e[28:])),
		})
	}
	return out
}

// longUnits are the 13 UTF-16 units one VFAT entry carries.
func longUnits(e []byte) []uint16 {
	var units []uint16
	for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
		for off := r[0]; off < r[1]; off += 2 {
			units = append(units, binary.LittleEndian.Uint16(e[off:]))
		}
	}
	return units
}

// trimUnits cuts a long name at its terminating zero.
func trimUnits(units []uint16) []uint16 {
	for i, u := range units {
		if u == 0 {
			return units[:i]
		}
	}
	return units
}

// shortString renders an 11-byte short name as NAME.EXT.
func shortString(n []byte, ntCase byte) string {
	base := strings.TrimRight(string(n[0:8]), " ")
	ext := strings.TrimRight(string(n[8:11]), " ")
	if ntCase&ntLowerBase != 0 {
		base = strings.ToLower(base)
	}
	if ntCase&ntLowerExt != 0 {
		ext = strings.ToLower(ext)
	}
	if ext == "" {
		return base
	}
	return base + "." + ext
}
