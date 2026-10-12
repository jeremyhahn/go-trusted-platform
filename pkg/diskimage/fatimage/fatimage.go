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

// Package fatimage writes a directory tree as a FAT16 volume image, and reads
// one back. It is how the media pipeline makes the Raspberry Pi's boot.img (a
// FAT ramdisk of the boot partition) without a container, a loop device, a
// mount or any host tool: the bytes are a pure function of the tree and the
// options, so the same tree always signs to the same digest.
//
// The writer emits what a Raspberry Pi bootloader and Linux read: 512-byte
// sectors, two FATs, a fixed root directory, long file names (a name that is
// not an uppercase 8.3 name gets VFAT entries and a numeric-tail short alias),
// and a cluster size chosen as the smallest that keeps the volume FAT16.
package fatimage

import (
	"encoding/binary"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	sectorSize  = 512
	entrySize   = 32
	maxClusters = 65524 // the most clusters a FAT16 volume holds
	minClusters = 4085  // the fewest: below this a driver reads the volume as FAT12
	lfnUnits    = 13    // UTF-16 units in one VFAT entry
	maxNameLen  = 255   // UTF-16 units in a long name
	minRootSize = 512   // root directory entries, the conventional minimum
	maxSectors  = 64    // sectors per cluster, the FAT limit

	attrDirectory = 0x10
	attrVolume    = 0x08
	attrLFN       = 0x0F
	ntLowerBase   = 0x08
	ntLowerExt    = 0x10

	endOfChain = 0xFFFF
	mediaFixed = 0xFFF8
)

// DefaultLabel is the volume label when Options.Label is empty.
const DefaultLabel = "BOOT"

// Options configure Build.
type Options struct {
	// Label is the volume label (at most 11 characters; DefaultLabel when
	// empty).
	Label string
	// Time stamps every entry; the zero value is 1980-01-01 00:00:00 UTC, the
	// FAT epoch, so a build is reproducible.
	Time time.Time
	// VolumeID is the volume serial number.
	VolumeID uint32
}

// node is one file or directory of the tree being written.
type node struct {
	name     string
	parent   *node
	isDir    bool
	data     []byte
	length   int // len(data)
	children []*node
	short    [11]byte
	ntCase   byte
	longName bool   // needs VFAT entries
	first    uint16 // first cluster; zero for an empty file
	clusters int
}

// Build writes src as a FAT16 volume image.
func Build(src fs.FS, opts Options) ([]byte, error) {
	label, err := volumeLabel(opts.Label)
	if err != nil {
		return nil, err
	}
	root := &node{isDir: true}
	if err := load(src, ".", root); err != nil {
		return nil, err
	}

	var all []*node
	collect(root, &all)
	rootEntries := minRootSize
	if n := (root.entryCount() + 1 + 15) / 16 * 16; n > rootEntries {
		rootEntries = n
	}
	if rootEntries > 0xFFFF {
		return nil, &TooLargeError{RootEntries: rootEntries}
	}

	sectorsPerCluster, used, err := chooseClusterSize(all)
	if err != nil {
		return nil, err
	}
	clusters := max(used, minClusters)
	fatSectors := ((clusters+2)*2 + sectorSize - 1) / sectorSize
	rootSectors := rootEntries * entrySize / sectorSize
	reserved := 1
	total := reserved + 2*fatSectors + rootSectors + clusters*sectorsPerCluster

	img := make([]byte, total*sectorSize)
	writeBootSector(img, label, opts.VolumeID, sectorsPerCluster, reserved, rootEntries, fatSectors, total)

	fat := make([]byte, fatSectors*sectorSize)
	binary.LittleEndian.PutUint16(fat[0:], mediaFixed)
	binary.LittleEndian.PutUint16(fat[2:], endOfChain)
	next := 2
	for _, n := range all {
		n.clusters = ceilDiv(n.size(), sectorsPerCluster*sectorSize)
		if n.clusters == 0 {
			continue
		}
		n.first = uint16(next)
		for i := 0; i < n.clusters; i++ {
			entry := uint16(next + i + 1)
			if i == n.clusters-1 {
				entry = endOfChain
			}
			binary.LittleEndian.PutUint16(fat[(next+i)*2:], entry)
		}
		next += n.clusters
	}
	copy(img[reserved*sectorSize:], fat)
	copy(img[(reserved+fatSectors)*sectorSize:], fat)

	stamp := newDOSTime(opts.Time)
	rootOff := (reserved + 2*fatSectors) * sectorSize
	rootSectorsBytes := rootSectors * sectorSize
	dataOff := rootOff + rootSectorsBytes
	rootDir := append(shortEntry(label, attrVolume, 0, 0, stamp, 0), root.dirBytes(0, stamp)...)
	copy(img[rootOff:rootOff+rootSectorsBytes], rootDir)
	for _, n := range all {
		if n.clusters == 0 {
			continue
		}
		off := dataOff + (int(n.first)-2)*sectorsPerCluster*sectorSize
		if n.isDir {
			copy(img[off:], n.dirBytes(n.parent.first, stamp))
			continue
		}
		copy(img[off:], n.data)
	}
	return img, nil
}

// volumeLabel validates and pads the label.
func volumeLabel(label string) ([11]byte, error) {
	if label == "" {
		label = DefaultLabel
	}
	var out [11]byte
	for i := range out {
		out[i] = ' '
	}
	if len(label) > len(out) {
		return out, &NameError{Path: label, Reason: "a volume label is at most 11 characters"}
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c < 0x20 || c > 0x7e || strings.IndexByte(`"*+,./:;<=>?[\]|`, c) >= 0 {
			return out, &NameError{Path: label, Reason: "a volume label is printable ASCII without " + `"*+,./:;<=>?[\]|`}
		}
		out[i] = c
	}
	return out, nil
}

// load reads the directory dir of src into n.
func load(src fs.FS, dir string, n *node) error {
	entries, err := fs.ReadDir(src, dir)
	if err != nil {
		return &ReadError{Path: dir, Err: err}
	}
	taken := map[[11]byte]bool{}
	folded := map[string]bool{}
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		if err := validateName(p, e.Name()); err != nil {
			return err
		}
		key := strings.ToUpper(e.Name())
		if folded[key] {
			return &NameError{Path: p, Reason: "the same name as another entry once case is ignored"}
		}
		folded[key] = true

		info, err := e.Info() // not fs.Stat: a symlink must show as one, not as its target
		if err != nil {
			return &ReadError{Path: p, Err: err}
		}
		child := &node{name: e.Name(), isDir: info.IsDir(), parent: n}
		child.short, child.longName, child.ntCase = shortName(e.Name(), taken)
		switch {
		case info.IsDir():
			if err := load(src, p, child); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if child.data, err = fs.ReadFile(src, p); err != nil {
				return &ReadError{Path: p, Err: err}
			}
			child.length = len(child.data)
		default:
			return &NotRegularError{Path: p, Mode: info.Mode().Type().String()}
		}
		n.children = append(n.children, child)
	}
	return nil
}

// validateName refuses what FAT cannot name.
func validateName(p, name string) error {
	if !utf8.ValidString(name) {
		return &NameError{Path: p, Reason: "the name is not valid UTF-8"}
	}
	if len(utf16.Encode([]rune(name))) > maxNameLen {
		return &NameError{Path: p, Reason: "the name is longer than 255 characters"}
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return &NameError{Path: p, Reason: "the name ends in a dot or a space"}
	}
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`"*/:<>?\|`, r) {
			return &NameError{Path: p, Reason: "the name holds a character FAT does not allow"}
		}
	}
	return nil
}

// collect lists every node under n, directories before their contents.
func collect(n *node, out *[]*node) {
	for _, c := range n.children {
		*out = append(*out, c)
		if c.isDir {
			collect(c, out)
		}
	}
}

// chooseClusterSize picks the smallest cluster size at which the tree fits a
// FAT16 volume, and returns the clusters it uses.
func chooseClusterSize(all []*node) (sectorsPerCluster, used int, err error) {
	for spc := 1; spc <= maxSectors; spc *= 2 {
		used = 0
		for _, n := range all {
			used += ceilDiv(n.size(), spc*sectorSize)
		}
		if used <= maxClusters {
			return spc, used, nil
		}
	}
	return 0, used, &TooLargeError{Clusters: used}
}

func ceilDiv(a, b int) int { return (a + b - 1) / b }

// size is the bytes n occupies: a file's length, a directory's entries plus
// "." and ".." and the terminating empty entry.
func (n *node) size() int {
	if !n.isDir {
		return n.length
	}
	return (n.entryCount() + 3) * entrySize
}

// entryCount is the directory slots n's children take: a short entry each,
// plus their VFAT entries.
func (n *node) entryCount() int {
	var count int
	for _, c := range n.children {
		count++
		if c.longName {
			count += ceilDiv(len(utf16.Encode([]rune(c.name))), lfnUnits)
		}
	}
	return count
}

// dirBytes is n's directory table: "." and ".." (except in the root), then
// each child's VFAT entries and short entry.
func (n *node) dirBytes(parentFirst uint16, stamp dosTime) []byte {
	var out []byte
	if n.name != "" {
		out = append(out, shortEntry(dotName(1), attrDirectory, n.first, 0, stamp, 0)...)
		out = append(out, shortEntry(dotName(2), attrDirectory, parentFirst, 0, stamp, 0)...)
	}
	for _, c := range n.children {
		if c.longName {
			for _, e := range longEntries(c.name, checksum(c.short)) {
				out = append(out, e...)
			}
		}
		attr, size := byte(0x20), uint32(c.length) // archive bit, as mkfs and Linux set it
		if c.isDir {
			attr, size = attrDirectory, 0
		}
		out = append(out, shortEntry(c.short, attr, c.first, size, stamp, c.ntCase)...)
	}
	return out
}

func dotName(dots int) [11]byte {
	name := [11]byte{' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
	for i := 0; i < dots; i++ {
		name[i] = '.'
	}
	return name
}

// shortEntry is one 32-byte short directory entry.
func shortEntry(name [11]byte, attr byte, first uint16, size uint32, stamp dosTime, ntCase byte) []byte {
	e := make([]byte, entrySize)
	copy(e[0:11], name[:])
	e[11] = attr
	e[12] = ntCase
	binary.LittleEndian.PutUint16(e[14:], stamp.time) // created
	binary.LittleEndian.PutUint16(e[16:], stamp.date)
	binary.LittleEndian.PutUint16(e[18:], stamp.date) // accessed
	binary.LittleEndian.PutUint16(e[22:], stamp.time) // written
	binary.LittleEndian.PutUint16(e[24:], stamp.date)
	binary.LittleEndian.PutUint16(e[26:], first)
	binary.LittleEndian.PutUint32(e[28:], size)
	return e
}

// longEntries are the VFAT entries of name, last part first as the directory
// stores them.
func longEntries(name string, sum byte) [][]byte {
	units := utf16.Encode([]rune(name))
	parts := ceilDiv(len(units), lfnUnits)
	padded := make([]uint16, parts*lfnUnits)
	for i := range padded {
		switch {
		case i < len(units):
			padded[i] = units[i]
		case i > len(units):
			padded[i] = 0xFFFF
		}
	}
	out := make([][]byte, 0, parts)
	for seq := parts; seq >= 1; seq-- {
		chunk := padded[(seq-1)*lfnUnits : seq*lfnUnits]
		e := make([]byte, entrySize)
		e[0] = byte(seq)
		if seq == parts {
			e[0] |= 0x40
		}
		e[11] = attrLFN
		e[13] = sum
		putUnits(e[1:11], chunk[0:5])
		putUnits(e[14:26], chunk[5:11])
		putUnits(e[28:32], chunk[11:13])
		out = append(out, e)
	}
	return out
}

func putUnits(dst []byte, units []uint16) {
	for i, u := range units {
		binary.LittleEndian.PutUint16(dst[i*2:], u)
	}
}

// checksum is the VFAT checksum of a short name.
func checksum(name [11]byte) byte {
	var sum byte
	for _, b := range name {
		sum = (sum&1)<<7 + sum>>1 + b
	}
	return sum
}

// shortName is the 8.3 name of name: itself when it already is an uppercase
// 8.3 name nothing in the directory holds, otherwise a numeric-tail alias that
// needs VFAT entries to carry the real name.
func shortName(name string, taken map[[11]byte]bool) (short [11]byte, long bool, ntCase byte) {
	if exact, exactCase, ok := exactShortName(name); ok && !taken[exact] {
		taken[exact] = true
		return exact, false, exactCase
	}
	base, ext := splitExt(strings.TrimLeft(name, "."))
	base, ext = aliasChars(base), aliasChars(ext)
	if base == "" {
		base = "_"
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	for n := 1; ; n++ {
		tail := "~" + strconv.Itoa(n)
		b := base
		if len(b) > 8-len(tail) {
			b = b[:8-len(tail)]
		}
		alias := packShort(b+tail, ext)
		if !taken[alias] {
			taken[alias] = true
			return alias, true, 0
		}
	}
}

// exactShortName reports name as an 8.3 short name when it is one already.
func exactShortName(name string) ([11]byte, byte, bool) {
	base, ext := splitExt(name)
	if base == "" || len(base) > 8 || len(ext) > 3 || strings.Contains(base, ".") {
		return [11]byte{}, 0, false
	}
	baseShort, lowerBase, ok := exactShortPart(base)
	if !ok {
		return [11]byte{}, 0, false
	}
	extShort, lowerExt, ok := exactShortPart(ext)
	if !ok {
		return [11]byte{}, 0, false
	}
	var ntCase byte
	if lowerBase {
		ntCase |= ntLowerBase
	}
	if lowerExt {
		ntCase |= ntLowerExt
	}
	return packShort(baseShort, extShort), ntCase, true
}

func exactShortPart(part string) (string, bool, bool) {
	var b strings.Builder
	hasLower, hasUpper := false, false
	for i := 0; i < len(part); i++ {
		c := part[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
			b.WriteByte(c - 'a' + 'A')
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			b.WriteByte(c)
		case shortChar(c):
			b.WriteByte(c)
		default:
			return "", false, false
		}
	}
	if hasLower && hasUpper {
		return "", false, false
	}
	return b.String(), hasLower, true
}

// shortChar reports whether c may appear in a short name as is.
func shortChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'()-@^_`{}~", c) >= 0
}

// aliasChars uppercases s and replaces what a short name cannot hold.
func aliasChars(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == ' ' || r == '.':
			continue
		case r < 0x80 && shortChar(byte(r)):
			b.WriteByte(byte(r))
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func splitExt(name string) (base, ext string) {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name, ""
	}
	return name[:i], name[i+1:]
}

func packShort(base, ext string) [11]byte {
	var out [11]byte
	for i := range out {
		out[i] = ' '
	}
	copy(out[0:8], base)
	copy(out[8:11], ext)
	return out
}

// dosTime is a FAT date and time.
type dosTime struct{ date, time uint16 }

func newDOSTime(t time.Time) dosTime {
	t = t.UTC()
	if t.Year() < 1980 {
		t = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return dosTime{
		date: uint16(t.Year()-1980)<<9 | uint16(t.Month())<<5 | uint16(t.Day()),
		time: uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2),
	}
}

// writeBootSector writes the BIOS parameter block of a FAT16 volume.
func writeBootSector(img []byte, label [11]byte, volumeID uint32, spc, reserved, rootEntries, fatSectors, total int) {
	b := img[:sectorSize]
	copy(b[0:3], []byte{0xEB, 0x3C, 0x90})
	copy(b[3:11], "MSWIN4.1")
	binary.LittleEndian.PutUint16(b[11:], sectorSize)
	b[13] = byte(spc)
	binary.LittleEndian.PutUint16(b[14:], uint16(reserved))
	b[16] = 2 // FATs
	binary.LittleEndian.PutUint16(b[17:], uint16(rootEntries))
	if total < 0x10000 {
		binary.LittleEndian.PutUint16(b[19:], uint16(total))
	} else {
		binary.LittleEndian.PutUint32(b[32:], uint32(total))
	}
	b[21] = 0xF8 // fixed media
	binary.LittleEndian.PutUint16(b[22:], uint16(fatSectors))
	binary.LittleEndian.PutUint16(b[24:], 63)  // sectors per track
	binary.LittleEndian.PutUint16(b[26:], 255) // heads
	b[36] = 0x80                               // drive number
	b[38] = 0x29                               // extended boot signature
	binary.LittleEndian.PutUint32(b[39:], volumeID)
	copy(b[43:54], label[:])
	copy(b[54:62], "FAT16   ")
	b[510], b[511] = 0x55, 0xAA
}
