package diskimage

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
)

// sectorSize is the MBR logical sector size.
const sectorSize = 512

// Partition is one MBR partition table entry.
type Partition struct {
	Index    int
	Type     byte
	Bootable bool
	// StartLBA and Sectors are in 512-byte sectors.
	StartLBA uint32
	Sectors  uint32
}

// OffsetBytes is the partition's byte offset in the image.
func (p Partition) OffsetBytes() int64 { return int64(p.StartLBA) * sectorSize }

// SizeBytes is the partition's length in bytes.
func (p Partition) SizeBytes() int64 { return int64(p.Sectors) * sectorSize }

// Report is what Inspect learns about an image.
type Report struct {
	Image      string
	SizeBytes  int64
	Partitions []Partition
	// ESP is partition 1 when it is a FAT32 (0x0c/0x0b) partition.
	ESP *Partition
	// LUKS2 is true when partition 2 starts with a LUKS2 header.
	LUKS2 bool
	// ESPFiles lists the files found on the ESP, root-relative.
	ESPFiles []string
	// UKIPath is the EFI/BOOT loader found, UKIMachine its COFF machine
	// (0xAA64 aarch64, 0x8664 x86-64) and UKISigned whether it carries a
	// security directory (an Authenticode signature).
	UKIPath    string
	UKIMachine uint16
	UKISigned  bool
	// InstallerLUKS is true when tpm2/installer.luks is present: the image
	// has not had its first boot.
	InstallerLUKS bool
	// Provisioned is true when EFI/TRUSTED_PLATFORM/PROVISIONED exists.
	Provisioned bool
	// ConfigTxt is the Raspberry Pi config.txt when present.
	ConfigTxt string
}

// String renders the report for the CLI.
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image: %s (%d MB)\n", r.Image, r.SizeBytes/(1024*1024))
	for _, p := range r.Partitions {
		boot := ""
		if p.Bootable {
			boot = " boot"
		}
		fmt.Fprintf(&b, "  p%d type=0x%02x start=%d sectors=%d (%d MB)%s\n", p.Index, p.Type, p.StartLBA, p.Sectors, p.SizeBytes()/(1024*1024), boot)
	}
	fmt.Fprintf(&b, "  ESP: %v  LUKS2 root: %v  installer.luks: %v  provisioned sentinel: %v\n", r.ESP != nil, r.LUKS2, r.InstallerLUKS, r.Provisioned)
	if r.UKIPath != "" {
		fmt.Fprintf(&b, "  UKI: %s machine=0x%04x signed=%v\n", r.UKIPath, r.UKIMachine, r.UKISigned)
	}
	if r.ConfigTxt != "" {
		fmt.Fprintf(&b, "  config.txt:\n")
		for _, line := range strings.Split(strings.TrimSpace(r.ConfigTxt), "\n") {
			fmt.Fprintf(&b, "    %s\n", line)
		}
	}
	if len(r.ESPFiles) > 0 {
		fmt.Fprintf(&b, "  ESP files (%d):\n", len(r.ESPFiles))
		for _, f := range r.ESPFiles {
			fmt.Fprintf(&b, "    %s\n", f)
		}
	}
	return b.String()
}

// Inspect reads an image's partition table and LUKS2 header in Go and lists
// the ESP through mtools (mdir/mcopy via the runner), so nothing is mounted
// and no privilege is needed.
func Inspect(ctx context.Context, path string, run runner.Runner) (*Report, error) {
	if run == nil {
		run = runner.Exec
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, &InspectError{Path: path, Reason: "cannot open", Err: err}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, &InspectError{Path: path, Reason: "cannot stat", Err: err}
	}
	report := &Report{Image: path, SizeBytes: info.Size()}

	mbr := make([]byte, sectorSize)
	if _, err := f.ReadAt(mbr, 0); err != nil {
		return nil, &InspectError{Path: path, Reason: "cannot read the MBR", Err: err}
	}
	parts, err := ParseMBR(mbr)
	if err != nil {
		return nil, &InspectError{Path: path, Reason: err.Error()}
	}
	report.Partitions = parts
	for i := range parts {
		if parts[i].Index == 1 && (parts[i].Type == 0x0c || parts[i].Type == 0x0b) {
			report.ESP = &parts[i]
		}
		if parts[i].Index == 2 {
			hdr := make([]byte, 8)
			if _, err := f.ReadAt(hdr, parts[i].OffsetBytes()); err == nil {
				report.LUKS2 = isLUKS2(hdr)
			}
		}
	}
	if report.ESP == nil {
		return report, nil
	}

	files, err := listFAT(ctx, run, path, report.ESP.OffsetBytes(), "")
	if err != nil {
		return nil, &InspectError{Path: path, Reason: "cannot list the EFI partition", Err: err}
	}
	report.ESPFiles = files
	for _, name := range files {
		switch {
		case strings.HasPrefix(name, "EFI/BOOT/BOOT") && strings.HasSuffix(name, ".EFI"):
			report.UKIPath = name
		case name == "tpm2/installer.luks":
			report.InstallerLUKS = true
		case name == "EFI/TRUSTED_PLATFORM/PROVISIONED":
			report.Provisioned = true
		}
	}
	tmp, err := os.MkdirTemp("", "diskimage-inspect-*")
	if err != nil {
		return nil, &InspectError{Path: path, Reason: "cannot create a temp dir", Err: err}
	}
	defer os.RemoveAll(tmp)
	if report.UKIPath != "" {
		local := filepath.Join(tmp, "uki.efi")
		if err := copyFromFAT(ctx, run, path, report.ESP.OffsetBytes(), report.UKIPath, local); err != nil {
			return nil, &InspectError{Path: path, Reason: "cannot copy the UKI out of the EFI partition", Err: err}
		}
		machine, signed, err := peMachine(local)
		if err != nil {
			return nil, &InspectError{Path: path, Reason: "the UKI is not a PE image", Err: err}
		}
		report.UKIMachine, report.UKISigned = machine, signed
	}
	for _, name := range files {
		if name == "config.txt" {
			local := filepath.Join(tmp, "config.txt")
			if err := copyFromFAT(ctx, run, path, report.ESP.OffsetBytes(), name, local); err == nil {
				if data, err := os.ReadFile(local); err == nil {
					report.ConfigTxt = string(data)
				}
			}
		}
	}
	return report, nil
}

// ParseMBR decodes the four primary partition entries of a 512-byte MBR.
func ParseMBR(sector []byte) ([]Partition, error) {
	if len(sector) < sectorSize {
		return nil, &configError{"MBR is shorter than one sector"}
	}
	if sector[510] != 0x55 || sector[511] != 0xaa {
		return nil, &configError{"no MBR boot signature (0x55AA)"}
	}
	var parts []Partition
	for i := 0; i < 4; i++ {
		e := sector[446+16*i : 446+16*(i+1)]
		if e[4] == 0 {
			continue
		}
		parts = append(parts, Partition{
			Index:    i + 1,
			Type:     e[4],
			Bootable: e[0] == 0x80,
			StartLBA: binary.LittleEndian.Uint32(e[8:12]),
			Sectors:  binary.LittleEndian.Uint32(e[12:16]),
		})
	}
	if len(parts) == 0 {
		return nil, &configError{"MBR has no partitions"}
	}
	return parts, nil
}

// luksMagic starts a LUKS header; bytes 6-7 carry the big-endian version.
var luksMagic = []byte("LUKS\xba\xbe")

// isLUKS2 reports whether hdr starts a LUKS version 2 header.
func isLUKS2(hdr []byte) bool {
	return len(hdr) >= 8 && bytes.Equal(hdr[:6], luksMagic) && binary.BigEndian.Uint16(hdr[6:8]) == 2
}

// mtoolsImage is the mtools -i spec for a partition inside an image.
// ExtractESP copies every file on the image's EFI system partition that
// keep accepts into dest, preserving the partition-relative path (forward
// slashes) — what a network boot server serves a Raspberry Pi from the
// same image the SD card carries. The returned names are the files
// copied, sorted.
func ExtractESP(ctx context.Context, image, dest string, keep func(name string) bool, run runner.Runner) ([]string, error) {
	if run == nil {
		run = runner.Exec
	}
	f, err := os.Open(image)
	if err != nil {
		return nil, &InspectError{Path: image, Reason: "cannot open", Err: err}
	}
	mbr := make([]byte, sectorSize)
	_, err = f.ReadAt(mbr, 0)
	_ = f.Close()
	if err != nil {
		return nil, &InspectError{Path: image, Reason: "cannot read the MBR", Err: err}
	}
	parts, err := ParseMBR(mbr)
	if err != nil {
		return nil, &InspectError{Path: image, Reason: err.Error()}
	}
	var esp *Partition
	for i := range parts {
		if parts[i].Index == 1 && (parts[i].Type == 0x0c || parts[i].Type == 0x0b) {
			esp = &parts[i]
		}
	}
	if esp == nil {
		return nil, &InspectError{Path: image, Reason: "no FAT partition 1 (the EFI system partition)"}
	}
	files, err := listFAT(ctx, run, image, esp.OffsetBytes(), "")
	if err != nil {
		return nil, &InspectError{Path: image, Reason: "cannot list the EFI partition", Err: err}
	}
	var copied []string
	for _, name := range files {
		if keep != nil && !keep(name) {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, &InspectError{Path: image, Reason: "cannot create " + filepath.Dir(target), Err: err}
		}
		if err := copyFromFAT(ctx, run, image, esp.OffsetBytes(), name, target); err != nil {
			return nil, &InspectError{Path: image, Reason: "cannot copy " + name, Err: err}
		}
		copied = append(copied, name)
	}
	return copied, nil
}

func mtoolsImage(image string, offset int64) string {
	return image + "@@" + strconv.FormatInt(offset, 10)
}

// listFAT lists every file under dir on the FAT partition, recursively,
// using mdir; names are returned root-relative with forward slashes.
func listFAT(ctx context.Context, run runner.Runner, image string, offset int64, dir string) ([]string, error) {
	out, err := run(ctx, "mdir", "-i", mtoolsImage(image, offset), "-/", "-b", "::/"+dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// -b prints ::/path; directories end with /.
		name := strings.TrimPrefix(line, "::/")
		if strings.HasSuffix(name, "/") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	return files, nil
}

// copyFromFAT copies one file out of the FAT partition with mcopy.
func copyFromFAT(ctx context.Context, run runner.Runner, image string, offset int64, name, dest string) error {
	_, err := run(ctx, "mcopy", "-n", "-i", mtoolsImage(image, offset), "::/"+name, dest)
	return err
}

// peMachine reports a PE image's COFF machine and whether its security
// directory (the Authenticode signature) is present.
func peMachine(path string) (uint16, bool, error) {
	f, err := pe.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	signed := false
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		signed = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0
	case *pe.OptionalHeader32:
		signed = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0
	}
	return f.Machine, signed, nil
}
