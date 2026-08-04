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

//go:build integration

package secureboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

// moduleSigMagic is the kernel's appended-signature marker (28 bytes
// including the trailing newline) and moduleSigTrailerLen is
// sizeof(struct module_signature).
const (
	moduleSigMagic      = "~Module signature appended~\n"
	moduleSigTrailerLen = 12
)

// hasModuleSignature reports whether data carries the kernel appended-
// signature trailer.
func hasModuleSignature(data []byte) bool {
	return len(data) > len(moduleSigMagic) && bytes.HasSuffix(data, []byte(moduleSigMagic))
}

// stripModuleSignature removes the appended CMS signature, the 12-byte
// struct module_signature and the magic marker from a signed module,
// returning the original unsigned module bytes.
func stripModuleSignature(t *testing.T, data []byte) []byte {
	t.Helper()
	if !hasModuleSignature(data) {
		t.Fatal("module has no appended signature to strip")
	}
	withoutMagic := data[:len(data)-len(moduleSigMagic)]
	if len(withoutMagic) < moduleSigTrailerLen {
		t.Fatal("module too short for module_signature trailer")
	}
	trailer := withoutMagic[len(withoutMagic)-moduleSigTrailerLen:]
	sigLen := binary.BigEndian.Uint32(trailer[8:12])
	body := withoutMagic[:len(withoutMagic)-moduleSigTrailerLen]
	if uint32(len(body)) < sigLen {
		t.Fatalf("module_signature sig_len %d exceeds module size %d", sigLen, len(body))
	}
	return body[:uint32(len(body))-sigLen]
}

// extractModuleSignature returns the raw CMS DER from a signed module.
func extractModuleSignature(t *testing.T, data []byte) []byte {
	t.Helper()
	if !hasModuleSignature(data) {
		t.Fatal("module has no appended signature")
	}
	withoutMagic := data[:len(data)-len(moduleSigMagic)]
	trailer := withoutMagic[len(withoutMagic)-moduleSigTrailerLen:]
	sigLen := binary.BigEndian.Uint32(trailer[8:12])
	body := withoutMagic[:len(withoutMagic)-moduleSigTrailerLen]
	if uint32(len(body)) < sigLen {
		t.Fatalf("module_signature sig_len %d exceeds module size %d", sigLen, len(body))
	}
	return body[uint32(len(body))-sigLen:]
}

// fipsModules is the parsed content of the FIPS modules tarball.
type fipsModules struct {
	// KernelVersion is the lib/modules/<kver> directory name.
	KernelVersion string
	// Files maps tarball paths (relative to lib/modules/<kver>/) to bytes.
	Files map[string][]byte
}

// loadFIPSModules reads modules-fips-<kver>.tar.gz into memory.
func loadFIPSModules(t *testing.T, tarPath string) *fipsModules {
	t.Helper()

	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatalf("open modules tarball: %v", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gunzip modules tarball: %v", err)
	}
	defer gz.Close()

	result := &fipsModules{Files: map[string][]byte{}}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read modules tarball: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Layout: lib/modules/<kver>/...
		name := strings.TrimPrefix(hdr.Name, "./")
		parts := strings.SplitN(name, "/", 4)
		if len(parts) < 4 || parts[0] != "lib" || parts[1] != "modules" {
			continue
		}
		if result.KernelVersion == "" {
			result.KernelVersion = parts[2]
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s from modules tarball: %v", hdr.Name, err)
		}
		result.Files[parts[3]] = data
	}

	if result.KernelVersion == "" {
		t.Fatal(ErrNoLoadableModule{Reason: "tarball contains no lib/modules/<kver> tree"})
	}
	return result
}

// candidatePreference orders zero-dependency modules by how likely their init
// is to succeed in a bare QEMU VM: NLS tables and generic crypto/lib modules
// register software-only providers and never touch hardware.
var candidatePreference = []string{"/nls/", "/crypto/", "/lib/", "/fs/"}

// pickInsmodCandidates returns up to max zero-dependency .ko paths (relative
// to the modules root) ordered by candidatePreference. It fails when
// modules.dep is missing or no zero-dependency module exists.
func pickInsmodCandidates(t *testing.T, mods *fipsModules, max int) []string {
	t.Helper()

	dep, ok := mods.Files["modules.dep"]
	if !ok {
		t.Fatal(ErrNoLoadableModule{Reason: "modules.dep not present in tarball"})
	}

	var zeroDep []string
	for _, line := range strings.Split(string(dep), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, deps, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(deps) != "" {
			continue
		}
		name = strings.TrimSpace(name)
		if !strings.HasSuffix(name, ".ko") {
			// Compressed modules cannot be fed to busybox insmod directly.
			continue
		}
		if _, present := mods.Files[name]; present {
			zeroDep = append(zeroDep, name)
		}
	}
	if len(zeroDep) == 0 {
		t.Fatal(ErrNoLoadableModule{Reason: "no zero-dependency uncompressed .ko in modules.dep"})
	}

	rank := func(p string) int {
		for i, pref := range candidatePreference {
			if strings.Contains(path.Dir(p)+"/", pref) {
				return i
			}
		}
		return len(candidatePreference)
	}
	sort.SliceStable(zeroDep, func(i, j int) bool { return rank(zeroDep[i]) < rank(zeroDep[j]) })

	if len(zeroDep) > max {
		zeroDep = zeroDep[:max]
	}
	return zeroDep
}

// buildTestKernelModule assembles a minimal, structurally valid ELF64
// relocatable object shaped like a kernel module (.ko): ELF header, a
// .modinfo section with license/name tags, .text, and a section header
// string table. It is NOT loadable by a kernel — it exists so the module
// signer is exercised against a realistic ELF payload without requiring
// kernel headers in the devcontainer.
func buildTestKernelModule() []byte {
	// Section bodies.
	text := []byte{0xC3} // ret
	modinfo := []byte("license=GPL\x00name=tp_sbtest\x00vermagic=0.0.0 SMP mod_unload\x00")
	shstrtab := []byte("\x00.text\x00.modinfo\x00.shstrtab\x00")
	// Offsets of the names inside shstrtab.
	const (
		nameText     = 1
		nameModinfo  = 7
		nameShstrtab = 16
	)

	const ehSize = 64
	const shSize = 64

	// File layout: ELF header | .text | .modinfo | .shstrtab | section headers.
	textOff := ehSize
	modinfoOff := textOff + len(text)
	shstrtabOff := modinfoOff + len(modinfo)
	shoff := shstrtabOff + len(shstrtab)
	// Align section header table to 8.
	shoff = align(shoff, 8)

	total := shoff + 4*shSize
	out := make([]byte, total)

	// ELF header.
	copy(out[0:], []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}) // ELF64 LSB
	binary.LittleEndian.PutUint16(out[16:], 1)             // e_type: ET_REL
	binary.LittleEndian.PutUint16(out[18:], 0x3E)          // e_machine: x86-64
	binary.LittleEndian.PutUint32(out[20:], 1)             // e_version
	binary.LittleEndian.PutUint64(out[40:], uint64(shoff)) // e_shoff
	binary.LittleEndian.PutUint16(out[52:], ehSize)        // e_ehsize
	binary.LittleEndian.PutUint16(out[58:], shSize)        // e_shentsize
	binary.LittleEndian.PutUint16(out[60:], 4)             // e_shnum
	binary.LittleEndian.PutUint16(out[62:], 3)             // e_shstrndx

	copy(out[textOff:], text)
	copy(out[modinfoOff:], modinfo)
	copy(out[shstrtabOff:], shstrtab)

	writeSH := func(idx int, name uint32, typ uint32, flags uint64, off, size int) {
		base := shoff + idx*shSize
		binary.LittleEndian.PutUint32(out[base:], name)
		binary.LittleEndian.PutUint32(out[base+4:], typ)
		binary.LittleEndian.PutUint64(out[base+8:], flags)
		binary.LittleEndian.PutUint64(out[base+24:], uint64(off))
		binary.LittleEndian.PutUint64(out[base+32:], uint64(size))
		binary.LittleEndian.PutUint64(out[base+48:], 1) // sh_addralign
	}

	// Index 0: SHT_NULL (all zero).
	writeSH(1, nameText, 1 /*SHT_PROGBITS*/, 0x6 /*ALLOC|EXECINSTR*/, textOff, len(text))
	writeSH(2, nameModinfo, 1 /*SHT_PROGBITS*/, 0x2 /*ALLOC*/, modinfoOff, len(modinfo))
	writeSH(3, nameShstrtab, 3 /*SHT_STRTAB*/, 0, shstrtabOff, len(shstrtab))

	return out
}
