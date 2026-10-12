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
	"bytes"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pattern is n bytes that differ at every offset (mod a prime), so a cluster
// written at the wrong place cannot match.
func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

// bootTree is the shape of a Raspberry Pi boot partition: 8.3 names, long
// names, nested directories, an empty file and a file of many clusters.
func bootTree() fstest.MapFS {
	return fstest.MapFS{
		"config.txt":                             {Data: []byte("kernel=kernel8.img\n")},
		"start4.elf":                             {Data: pattern(3 * 1024)},
		"kernel8.img":                            {Data: pattern(300 * 1024)},
		"bcm2711-rpi-4-b.dtb":                    {Data: pattern(1500)},
		"bcm2711-rpi-400.dtb":                    {Data: pattern(1501)},
		"overlays/tpm-soft-spi.dtbo":             {Data: pattern(700)},
		"overlays/disable-bt.dtbo":               {Data: pattern(512)},
		"EFI/BOOT/BOOTAA64.EFI":                  {Data: pattern(4096)},
		"empty.flag":                             {},
		"a-name-that-needs-three-vfat-slots.bin": {Data: []byte("long")},
		"überschrift.txt":                        {Data: []byte("unicode")},
	}
}

func TestBuild_RoundTripsABootTree(t *testing.T) {
	tree := bootTree()

	img, err := Build(tree, Options{Label: "RPIBOOT"})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	assert.Equal(t, "RPIBOOT", opened.Label())
	files, err := opened.Files()
	require.NoError(t, err)
	want := make([]string, 0, len(tree))
	for name := range tree {
		want = append(want, name)
	}
	assert.ElementsMatch(t, want, files)

	for name, f := range tree {
		got, err := opened.ReadFile(name)
		require.NoError(t, err, name)
		assert.True(t, bytes.Equal(f.Data, got), "%s: contents differ (%d bytes, want %d)", name, len(got), len(f.Data))
	}
}

func TestBuild_ReadFileIgnoresCase(t *testing.T) {
	img, err := Build(bootTree(), Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	got, err := opened.ReadFile("/efi/boot/bootaa64.efi")
	require.NoError(t, err)
	assert.Equal(t, pattern(4096), got)
	assert.Equal(t, DefaultLabel, opened.Label())
}

func TestBuild_IsReproducible(t *testing.T) {
	a, err := Build(bootTree(), Options{})
	require.NoError(t, err)
	b, err := Build(bootTree(), Options{})
	require.NoError(t, err)
	assert.True(t, bytes.Equal(a, b), "the same tree and options must give the same bytes: boot.sig signs them")

	c, err := Build(bootTree(), Options{Time: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)})
	require.NoError(t, err)
	assert.False(t, bytes.Equal(a, c), "the timestamp is part of the image")
}

func TestBuild_IsAFAT16Volume(t *testing.T) {
	img, err := Build(fstest.MapFS{"a": {Data: []byte("x")}}, Options{VolumeID: 0xCAFEF00D})
	require.NoError(t, err)

	assert.Equal(t, "FAT16   ", string(img[54:62]))
	assert.Equal(t, uint16(0xAA55), binary.LittleEndian.Uint16(img[510:]))
	assert.Equal(t, uint32(0xCAFEF00D), binary.LittleEndian.Uint32(img[39:]))
	fatSectors := int(binary.LittleEndian.Uint16(img[22:]))
	fat1 := img[sectorSize : sectorSize+fatSectors*sectorSize]
	fat2 := img[sectorSize+fatSectors*sectorSize : sectorSize+2*fatSectors*sectorSize]
	assert.Equal(t, fat1, fat2, "both FATs are identical")
	assert.Equal(t, uint16(mediaFixed), binary.LittleEndian.Uint16(fat1))
	assert.Equal(t, uint16(endOfChain), binary.LittleEndian.Uint16(fat1[4:]), "the single cluster ends its chain")

	opened, err := Open(img)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, opened.clusters, minClusters)
	assert.Equal(t, "BOOT       ", string(img[opened.rootOff:opened.rootOff+11]))
	assert.Equal(t, byte(attrVolume), img[opened.rootOff+11])
}

func TestBuild_GrowsTheRootDirectoryForManyEntries(t *testing.T) {
	tree := fstest.MapFS{}
	for i := 0; i < 700; i++ {
		tree["file-with-a-long-name-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)] = &fstest.MapFile{Data: []byte{byte(i)}}
	}
	img, err := Build(tree, Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)
	files, err := opened.Files()
	require.NoError(t, err)
	assert.Len(t, files, len(tree))
	assert.Greater(t, opened.rootEntries, minRootSize)
}

func TestChooseClusterSize(t *testing.T) {
	file := func(size int) *node { return &node{name: "f", length: size} }

	spc, used, err := chooseClusterSize([]*node{file(30 << 20)})
	require.NoError(t, err)
	assert.Equal(t, 1, spc, "a 30 MiB tree fits FAT16 with 512-byte clusters")
	assert.Equal(t, 30<<20/sectorSize, used)

	spc, _, err = chooseClusterSize([]*node{file(40 << 20)})
	require.NoError(t, err)
	assert.Equal(t, 2, spc, "more than 65524 clusters at 512 bytes doubles the cluster")

	_, _, err = chooseClusterSize([]*node{file(3 << 30)})
	var tooLarge *TooLargeError
	assert.ErrorAs(t, err, &tooLarge)
}

func TestShortName(t *testing.T) {
	taken := map[[11]byte]bool{}
	cases := []struct {
		name   string
		short  string
		long   bool
		ntCase byte
	}{
		{"BOOTAA64.EFI", "BOOTAA64EFI", false, 0},
		{"LICENCE", "LICENCE    ", false, 0},
		{"config.txt", "CONFIG  TXT", false, ntLowerBase | ntLowerExt},
		{"start4.elf", "START4  ELF", false, ntLowerBase | ntLowerExt},
		{"Config.txt", "CONFIG~1TXT", true, 0},
		{"bcm2711-rpi-4-b.dtb", "BCM271~1DTB", true, 0},
		{"bcm2711-rpi-400.dtb", "BCM271~2DTB", true, 0},
		{".hidden", "HIDDEN~1   ", true, 0},
		{"naïve name.x", "NA_VEN~1X  ", true, 0},
		{"BOOTAA64.EFI", "BOOTAA~1EFI", true, 0}, // the exact short name is taken
	}
	for _, c := range cases {
		short, long, ntCase := shortName(c.name, taken)
		assert.Equal(t, c.short, string(short[:]), c.name)
		assert.Equal(t, c.long, long, c.name)
		assert.Equal(t, c.ntCase, ntCase, c.name)
	}
}

func TestLongEntries(t *testing.T) {
	name := "bcm2711-rpi-4-b.dtb" // 19 units: two parts
	entries := longEntries(name, 0x5A)
	require.Len(t, entries, 2)

	assert.Equal(t, byte(2|0x40), entries[0][0], "the last part comes first, marked")
	assert.Equal(t, byte(1), entries[1][0])
	for _, e := range entries {
		assert.Equal(t, byte(attrLFN), e[11])
		assert.Equal(t, byte(0x5A), e[13])
	}
	// The second part holds the name's last six units, a zero terminator, then
	// 0xFFFF fill.
	units := longUnits(entries[0])
	assert.Equal(t, uint16('-'), units[0])
	assert.Equal(t, uint16('b'), units[5])
	assert.Equal(t, uint16(0), units[6], "the name ends in a zero unit")
	assert.Equal(t, uint16(0xFFFF), units[7])
	assert.Equal(t, uint16('b'), longUnits(entries[1])[0], "the first part holds the name's first units")
}

func TestChecksum(t *testing.T) {
	assert.Equal(t, byte(0), checksum([11]byte{}))
	last := [11]byte{10: 1}
	assert.Equal(t, byte(1), checksum(last))
	first := [11]byte{0: 1}
	assert.Equal(t, byte(0x40), checksum(first), "a byte rotates right through the ten steps after it")
}

func TestBuild_Errors(t *testing.T) {
	t.Run("a name FAT cannot hold", func(t *testing.T) {
		for _, name := range []string{"a*b", "a:b", "trailing ", "tab\tname", "q?"} {
			_, err := Build(fstest.MapFS{name: {Data: []byte("x")}}, Options{})
			var nameErr *NameError
			assert.ErrorAs(t, err, &nameErr, name)
		}
	})
	t.Run("a name longer than 255 characters", func(t *testing.T) {
		_, err := Build(fstest.MapFS{strings.Repeat("n", 256): {}}, Options{})
		var nameErr *NameError
		assert.ErrorAs(t, err, &nameErr)
	})
	t.Run("two names that differ only in case", func(t *testing.T) {
		_, err := Build(fstest.MapFS{"Config.txt": {}, "config.TXT": {}}, Options{})
		var nameErr *NameError
		assert.ErrorAs(t, err, &nameErr)
	})
	t.Run("a bad volume label", func(t *testing.T) {
		for _, label := range []string{"WAYTOOLONGLABEL", "BAD/LABEL", "tab\t"} {
			_, err := Build(fstest.MapFS{}, Options{Label: label})
			var nameErr *NameError
			assert.ErrorAs(t, err, &nameErr, label)
		}
	})
	t.Run("an entry that is neither a file nor a directory", func(t *testing.T) {
		_, err := Build(fstest.MapFS{"dev": {Mode: fs.ModeDevice}}, Options{})
		var notRegular *NotRegularError
		assert.ErrorAs(t, err, &notRegular)
	})
	t.Run("a symlink is not followed", func(t *testing.T) {
		outside := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside the tree"), 0o644))
		for name, target := range map[string]string{
			"file": filepath.Join(outside, "secret.txt"),
			"dir":  outside,
		} {
			src := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(src, "config.txt"), []byte("x"), 0o644))
			require.NoError(t, os.Symlink(target, filepath.Join(src, "link")))

			_, err := Build(os.DirFS(src), Options{})
			var notRegular *NotRegularError
			require.ErrorAs(t, err, &notRegular, name)
			assert.Equal(t, "link", notRegular.Path, name)
		}
	})
}

func TestOpen_Errors(t *testing.T) {
	good, err := Build(fstest.MapFS{"a.txt": {Data: []byte("x")}}, Options{})
	require.NoError(t, err)

	corrupt := func(mutate func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		mutate(b)
		return b
	}
	cases := map[string][]byte{
		"shorter than a boot sector": good[:100],
		"no signature":               corrupt(func(b []byte) { b[510] = 0 }),
		"sectors of 1024":            corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[11:], 1024) }),
		"clusters not a power of 2":  corrupt(func(b []byte) { b[13] = 3 }),
		"a FAT32 boot sector":        corrupt(func(b []byte) { binary.LittleEndian.PutUint16(b[22:], 0) }),
		"truncated":                  good[:len(good)-sectorSize],
		"a FAT12 cluster count":      corrupt(func(b []byte) { b[13] = 64 }),
	}
	for name, data := range cases {
		_, err := Open(data)
		var formatErr *FormatError
		assert.ErrorAs(t, err, &formatErr, name)
	}
}

func TestOpen_RejectsInconsistentGeometry(t *testing.T) {
	good, err := Build(fstest.MapFS{"a.txt": {Data: []byte("x")}}, Options{})
	require.NoError(t, err)

	tooSmallFAT := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(tooSmallFAT[22:], 1)
	_, err = Open(tooSmallFAT)
	var geometryErr *GeometryError
	require.ErrorAs(t, err, &geometryErr)
	assert.Equal(t, "FAT", geometryErr.Field)

	layoutPastImage := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(layoutPastImage[14:], uint16(len(good)/sectorSize))
	_, err = Open(layoutPastImage)
	require.ErrorAs(t, err, &geometryErr)
}

// rootDirEntries returns the root directory's entries for subdirectories by
// short name; the slices alias the image, so a test can corrupt it through them.
func rootDirEntries(opened *Image) map[string][]byte {
	out := map[string][]byte{}
	root := opened.rootBytes()
	for off := 0; off+entrySize <= len(root); off += entrySize {
		e := root[off : off+entrySize]
		if e[0] == 0x00 {
			break
		}
		if e[11]&attrDirectory == 0 || e[0] == '.' {
			continue
		}
		out[shortString(e[0:11], e[12])] = e
	}
	return out
}

func TestFiles_RefusesCrossLinkedDirectories(t *testing.T) {
	img, err := Build(fstest.MapFS{
		"DIR1/A.TXT": {Data: []byte("a")},
		"DIR2/B.TXT": {Data: []byte("b")},
	}, Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	dirs := rootDirEntries(opened)
	dir1 := binary.LittleEndian.Uint16(dirs["DIR1"][26:])
	require.NotZero(t, dir1)
	binary.LittleEndian.PutUint16(dirs["DIR2"][26:], dir1)

	_, err = opened.Files()
	var formatErr *FormatError
	require.ErrorAs(t, err, &formatErr)
}

// TestFiles_RefusesADirectoryStartingMidChain: directory B starting at a
// later cluster of directory A's chain shares data with A even though no two
// directories start at the same cluster.
func TestFiles_RefusesADirectoryStartingMidChain(t *testing.T) {
	img, err := Build(fstest.MapFS{
		"DIR1/A.TXT": {Data: []byte("a")},
		"DIR2/B.TXT": {Data: []byte("b")},
	}, Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	dirs := rootDirEntries(opened)
	dir1 := int(binary.LittleEndian.Uint16(dirs["DIR1"][26:]))
	dir2 := binary.LittleEndian.Uint16(dirs["DIR2"][26:])
	binary.LittleEndian.PutUint16(opened.fat[dir1*2:], dir2)

	_, err = opened.Files()
	var formatErr *FormatError
	require.ErrorAs(t, err, &formatErr)
	assert.Contains(t, formatErr.Reason, "more than once")
}

func FuzzOpenFiles(f *testing.F) {
	seed, err := Build(fstest.MapFS{"config.txt": {Data: []byte("arm_64bit=1\n")}}, Options{})
	require.NoError(f, err)
	f.Add(seed)
	fatTooSmall := append([]byte(nil), seed...)
	binary.LittleEndian.PutUint16(fatTooSmall[22:], 1)
	f.Add(fatTooSmall)

	f.Fuzz(func(t *testing.T, data []byte) {
		img, err := Open(data)
		if err != nil {
			return
		}
		_, _ = img.Files()
	})
}

func TestReadFile_Errors(t *testing.T) {
	img, err := Build(fstest.MapFS{
		"dir/file.txt": {Data: []byte("x")},
		"top.txt":      {Data: []byte("y")},
	}, Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	for _, p := range []string{"missing", "dir", "top.txt/inside", "dir/missing"} {
		_, err := opened.ReadFile(p)
		var notFound *NotFoundError
		assert.ErrorAs(t, err, &notFound, p)
	}
}

func TestReadFile_RefusesAChainThatLoops(t *testing.T) {
	img, err := Build(fstest.MapFS{"big.bin": {Data: pattern(2048)}}, Options{})
	require.NoError(t, err)
	opened, err := Open(img)
	require.NoError(t, err)

	// Point the file's last cluster back at its first.
	last := 2 + 2048/(opened.spc*sectorSize) - 1
	binary.LittleEndian.PutUint16(opened.fat[last*2:], 2)

	_, err = opened.ReadFile("big.bin")
	var formatErr *FormatError
	assert.ErrorAs(t, err, &formatErr)
}
