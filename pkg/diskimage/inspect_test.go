package diskimage

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeImage writes a sparse image with an MBR (p1 FAT32 at LBA 2048, p2
// Linux at LBA 1050624) and, when luks is set, a LUKS2 magic at p2.
func writeImage(t *testing.T, luks bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mbr := make([]byte, 512)
	entry := func(i int, boot byte, typ byte, start, sectors uint32) {
		e := mbr[446+16*i:]
		e[0] = boot
		e[4] = typ
		binary.LittleEndian.PutUint32(e[8:], start)
		binary.LittleEndian.PutUint32(e[12:], sectors)
	}
	entry(0, 0x80, 0x0c, 2048, 1048576)
	entry(1, 0, 0x83, 1050624, 2097152)
	mbr[510], mbr[511] = 0x55, 0xaa
	if _, err := f.WriteAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	if luks {
		hdr := append([]byte("LUKS\xba\xbe"), 0, 2)
		if _, err := f.WriteAt(hdr, int64(1050624)*512); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(int64(1050624+2097152) * 512); err != nil {
		t.Fatal(err)
	}
	return path
}

// mtoolsRunner fakes mdir/mcopy against a virtual ESP.
type mtoolsRunner struct {
	files map[string][]byte
	calls [][]string
	fail  string
}

func (m *mtoolsRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, append([]string{name}, args...))
	if m.fail != "" && name == m.fail {
		return []byte("boom"), errors.New("exit 1")
	}
	switch name {
	case "mdir":
		var out strings.Builder
		out.WriteString("::/EFI/\n")
		for path := range m.files {
			out.WriteString("::/" + path + "\n")
		}
		return []byte(out.String()), nil
	case "mcopy":
		src := strings.TrimPrefix(args[len(args)-2], "::/")
		data, ok := m.files[src]
		if !ok {
			return nil, errors.New("no such file")
		}
		return nil, os.WriteFile(args[len(args)-1], data, 0o644)
	}
	return nil, nil
}

// minimalPE builds a PE32+ header for the given machine with an optional
// security directory.
func minimalPE(machine uint16, signed bool) []byte {
	pe := make([]byte, 0x200)
	copy(pe, []byte("MZ"))
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x80)
	copy(pe[0x80:], []byte("PE\x00\x00"))
	binary.LittleEndian.PutUint16(pe[0x84:], machine)
	binary.LittleEndian.PutUint16(pe[0x86:], 0)   // sections
	binary.LittleEndian.PutUint16(pe[0x94:], 240) // optional header size
	binary.LittleEndian.PutUint16(pe[0x98:], 0x20b)
	binary.LittleEndian.PutUint32(pe[0x98+108:], 16) // NumberOfRvaAndSizes
	if signed {
		// data directory 4 (security) at offset 112 + 4*8 in the optional header
		binary.LittleEndian.PutUint32(pe[0x98+112+32:], 0x1000)
		binary.LittleEndian.PutUint32(pe[0x98+112+36:], 0x100)
	}
	return pe
}

func TestParseMBR(t *testing.T) {
	path := writeImage(t, true)
	sector := make([]byte, 512)
	f, _ := os.Open(path)
	defer f.Close()
	if _, err := f.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	parts, err := ParseMBR(sector)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || parts[0].Type != 0x0c || !parts[0].Bootable || parts[0].StartLBA != 2048 || parts[1].Type != 0x83 || parts[1].OffsetBytes() != int64(1050624)*512 {
		t.Errorf("parts = %+v", parts)
	}
	if _, err := ParseMBR(make([]byte, 512)); err == nil {
		t.Error("MBR without signature accepted")
	}
	if _, err := ParseMBR(make([]byte, 100)); err == nil {
		t.Error("short sector accepted")
	}
	empty := make([]byte, 512)
	empty[510], empty[511] = 0x55, 0xaa
	if _, err := ParseMBR(empty); err == nil {
		t.Error("MBR without partitions accepted")
	}
}

func TestInspectReportsImageContents(t *testing.T) {
	path := writeImage(t, true)
	esp := &mtoolsRunner{files: map[string][]byte{
		"EFI/BOOT/BOOTAA64.EFI":            minimalPE(0xAA64, true),
		"EFI/TRUSTED_PLATFORM/PROVISIONED": []byte("TRUSTED_PLATFORM=1\n"),
		"tpm2/installer.luks":              []byte("luks"),
		"config.txt":                       []byte("arm_64bit=1\nkernel=kernel8.img\n"),
		"kernel8.img":                      []byte("u-boot"),
	}}
	report, err := Inspect(context.Background(), path, esp.run)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if report.ESP == nil || !report.LUKS2 || !report.InstallerLUKS || !report.Provisioned {
		t.Errorf("report flags = %+v", report)
	}
	if report.UKIPath != "EFI/BOOT/BOOTAA64.EFI" || report.UKIMachine != 0xAA64 || !report.UKISigned {
		t.Errorf("UKI = %s 0x%x signed=%v", report.UKIPath, report.UKIMachine, report.UKISigned)
	}
	if !strings.Contains(report.ConfigTxt, "kernel=kernel8.img") || len(report.ESPFiles) != 5 {
		t.Errorf("config.txt=%q files=%v", report.ConfigTxt, report.ESPFiles)
	}
	text := report.String()
	for _, want := range []string{"p1 type=0x0c", "boot", "LUKS2 root: true", "machine=0xaa64", "signed=true", "kernel=kernel8.img"} {
		if !strings.Contains(text, want) {
			t.Errorf("String() lacks %q:\n%s", want, text)
		}
	}
	// mdir is asked for the ESP at its byte offset.
	if !strings.Contains(strings.Join(esp.calls[0], " "), path+"@@1048576") {
		t.Errorf("mdir call = %v", esp.calls[0])
	}
}

func TestInspectFailures(t *testing.T) {
	var ierr *InspectError
	if _, err := Inspect(context.Background(), filepath.Join(t.TempDir(), "missing.img"), (&mtoolsRunner{}).run); !errors.As(err, &ierr) {
		t.Errorf("missing image error = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.img")
	if err := os.WriteFile(bad, make([]byte, 512), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), bad, (&mtoolsRunner{}).run); !errors.As(err, &ierr) {
		t.Errorf("no-MBR image error = %v", err)
	}
	path := writeImage(t, false)
	if _, err := Inspect(context.Background(), path, (&mtoolsRunner{fail: "mdir"}).run); !errors.As(err, &ierr) {
		t.Errorf("mdir failure error = %v", err)
	}
	// An unsigned x86 UKI is reported, not rejected; a non-PE loader is an error.
	r, err := Inspect(context.Background(), path, (&mtoolsRunner{files: map[string][]byte{"EFI/BOOT/BOOTX64.EFI": minimalPE(0x8664, false)}}).run)
	if err != nil || r.UKIMachine != 0x8664 || r.UKISigned || r.LUKS2 {
		t.Errorf("x86 report = %+v, %v", r, err)
	}
	if _, err := Inspect(context.Background(), path, (&mtoolsRunner{files: map[string][]byte{"EFI/BOOT/BOOTAA64.EFI": []byte("not a PE")}}).run); !errors.As(err, &ierr) {
		t.Errorf("non-PE loader error = %v", err)
	}
	if _, err := Inspect(context.Background(), path, (&mtoolsRunner{files: map[string][]byte{"EFI/BOOT/BOOTAA64.EFI": minimalPE(0xAA64, false)}, fail: "mcopy"}).run); !errors.As(err, &ierr) {
		t.Errorf("mcopy failure error = %v", err)
	}
	if isLUKS2([]byte("LUKS\xba\xbe\x00\x01")) || !isLUKS2([]byte("LUKS\xba\xbe\x00\x02")) || isLUKS2([]byte("short")) {
		t.Error("isLUKS2 misclassifies headers")
	}
}
