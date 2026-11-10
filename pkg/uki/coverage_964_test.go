package uki

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIOError is the cause a failingReader or failingWriter reports.
type testIOError struct{}

func (testIOError) Error() string { return "test i/o failure" }

var errTestRead = testIOError{}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errTestRead }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errTestRead }

// stubPE returns an in-memory EFI stub with header room for ten more sections.
func stubPE() []byte {
	return authenticodetest.SectionedPE(1, 400)
}

// stubWithFreeSlots returns an EFI stub whose header has room for exactly n
// more section headers, filling the spare room with placeholder sections.
func stubWithFreeSlots(t *testing.T, n int) []byte {
	t.Helper()
	p, err := newPEPatcher(authenticodetest.SectionedPE(1, 0))
	require.NoError(t, err)
	free := func() int {
		tableEnd := p.sectionTableBase + uint32(p.numberOfSections)*sectionHeaderSize
		return (int(p.firstSectionRawData) - int(tableEnd)) / sectionHeaderSize
	}
	require.GreaterOrEqual(t, free(), n)
	for free() > n {
		require.NoError(t, p.addSection(".fill", []byte("F"), 0x40000040))
	}
	return p.bytes()
}

// fullUKI returns a UKI carrying every optional component.
func fullUKI() *UKI {
	return &UKI{
		Kernel:     strings.NewReader("KERNEL"),
		Initramfs:  strings.NewReader("INITRD"),
		Cmdline:    "root=/dev/sda1 ro",
		OSRelease:  "ID=test",
		Stub:       bytes.NewReader(stubPE()),
		Microcode:  strings.NewReader("UCODE"),
		Splash:     strings.NewReader("SPLASH"),
		DeviceTree: strings.NewReader("DTB"),
		SBAT:       "sbat,1",
	}
}

func readAllString(t *testing.T, r io.Reader) string {
	t.Helper()
	require.NotNil(t, r)
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(bytes.TrimRight(data, "\x00"))
}

func TestBuilder_Build_RoundTripsThroughParser(t *testing.T) {
	logger := testLogger(t)
	b := NewBuilder(logger)
	require.NoError(t, b.AddSection(".custom", []byte("CUSTOM")))

	var out bytes.Buffer
	require.NoError(t, b.Build(fullUKI(), &out))

	parsed, err := NewParser(logger).Parse(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, "KERNEL", readAllString(t, parsed.Kernel))
	assert.Equal(t, "INITRD", readAllString(t, parsed.Initramfs))
	assert.Equal(t, "root=/dev/sda1 ro", parsed.Cmdline)
	assert.Equal(t, "ID=test", strings.TrimRight(parsed.OSRelease, "\x00"))
	assert.Equal(t, "UCODE", readAllString(t, parsed.Microcode))
	assert.Equal(t, "SPLASH", readAllString(t, parsed.Splash))
	assert.Equal(t, "DTB", readAllString(t, parsed.DeviceTree))
	assert.Equal(t, "sbat,1", strings.TrimRight(parsed.SBAT, "\x00"))

	names, err := NewParser(logger).ListSections(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	// The stub's own section comes first, then the UKI sections in boot order,
	// then custom sections.
	assert.Equal(t,
		[]string{".osrel", ".cmdline", ".ucode", ".splash", ".linux", ".initrd", ".dtb", ".sbat", ".custom"},
		names[1:])

	custom, err := NewParser(logger).ExtractSection(bytes.NewReader(out.Bytes()), ".custom")
	require.NoError(t, err)
	assert.Equal(t, "CUSTOM", string(bytes.TrimRight(custom, "\x00")))
}

func TestBuilder_Build_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(u *UKI)
		output  io.Writer
		wantMsg string
		wantIO  bool
	}{
		{"invalid stub", func(u *UKI) { u.Stub = strings.NewReader("not a PE") }, nil, "failed to parse kernel as PE", false},
		{"stub read", func(u *UKI) { u.Stub = failingReader{} }, nil, "failed to load EFI stub", true},
		{"kernel read", func(u *UKI) { u.Kernel = failingReader{} }, nil, "failed to read kernel", true},
		{"initramfs read", func(u *UKI) { u.Initramfs = failingReader{} }, nil, "failed to read initramfs", true},
		{"microcode read", func(u *UKI) { u.Microcode = failingReader{} }, nil, "failed to read microcode", true},
		{"splash read", func(u *UKI) { u.Splash = failingReader{} }, nil, "failed to read splash", true},
		{"device tree read", func(u *UKI) { u.DeviceTree = failingReader{} }, nil, "failed to read device tree", true},
		{"no header space", func(u *UKI) { u.Stub = bytes.NewReader(stubWithFreeSlots(t, 0)) }, nil, "failed to add section .osrel", false},
		{"output write", func(u *UKI) {}, failingWriter{}, "failed to write UKI", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := fullUKI()
			tt.mutate(u)
			out := tt.output
			if out == nil {
				out = &bytes.Buffer{}
			}

			err := NewBuilder(testLogger(t)).Build(u, out)
			require.Error(t, err)
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.Equal(t, tt.wantIO, errors.Is(err, errTestRead))
		})
	}
}

func TestBuilder_Build_NoSpaceForCustomSection(t *testing.T) {
	b := NewBuilder(testLogger(t))
	require.NoError(t, b.AddSection(".custom", []byte("x")))
	u := &UKI{
		Kernel:    strings.NewReader("K"),
		Initramfs: strings.NewReader("I"),
		Cmdline:   "c",
		// Room for exactly the three required sections.
		Stub: bytes.NewReader(stubWithFreeSlots(t, 3)),
	}

	err := b.Build(u, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to add custom section .custom")
	var noSpace *ErrNoHeaderSpace
	assert.ErrorAs(t, err, &noSpace)
}

func TestBuilder_LoadStub_DefaultPathMissing(t *testing.T) {
	b := NewBuilder(testLogger(t)).(*builder)
	b.stubPath = filepath.Join(t.TempDir(), "missing.efi.stub")
	u := &UKI{Kernel: strings.NewReader("K"), Initramfs: strings.NewReader("I"), Cmdline: "c"}

	err := b.Build(u, &bytes.Buffer{})
	require.Error(t, err)
	var cmdErr *CommandOutputError
	require.ErrorAs(t, err, &cmdErr)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, err.Error(), "install systemd-efistub package")
}

func TestBuilder_LoadStub_DefaultPathUsed(t *testing.T) {
	b := NewBuilder(testLogger(t)).(*builder)
	b.stubPath = filepath.Join(t.TempDir(), "linux.efi.stub")
	require.NoError(t, os.WriteFile(b.stubPath, stubPE(), 0o600))
	u := &UKI{Kernel: strings.NewReader("K"), Initramfs: strings.NewReader("I"), Cmdline: "c"}

	var out bytes.Buffer
	require.NoError(t, b.Build(u, &out))
	names, err := NewParser(testLogger(t)).ListSections(&out)
	require.NoError(t, err)
	assert.Equal(t, []string{".cmdline", ".linux", ".initrd"}, names[1:])
}

func TestBuilder_BuildFile(t *testing.T) {
	logger := testLogger(t)
	path := filepath.Join(t.TempDir(), "uki.efi")

	require.NoError(t, NewBuilder(logger).BuildFile(fullUKI(), path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	parsed, err := NewParser(logger).ParseFile(path)
	require.NoError(t, err)
	assert.Equal(t, "root=/dev/sda1 ro", parsed.Cmdline)
}

func TestBuilder_BuildFile_Errors(t *testing.T) {
	logger := testLogger(t)

	t.Run("create fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing-dir", "uki.efi")
		err := NewBuilder(logger).BuildFile(fullUKI(), path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create output file")
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("build fails and removes the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "uki.efi")
		u := fullUKI()
		u.Kernel = failingReader{}
		err := NewBuilder(logger).BuildFile(u, path)
		require.ErrorIs(t, err, errTestRead)
		_, statErr := os.Stat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

// buildWithSections assembles a PE carrying exactly the given sections.
func buildWithSections(t *testing.T, sections map[string]string) []byte {
	t.Helper()
	p, err := newPEPatcher(stubPE())
	require.NoError(t, err)
	for _, name := range []string{".linux", ".initrd", ".cmdline"} {
		if data, ok := sections[name]; ok {
			require.NoError(t, p.addSection(name, []byte(data), 0x40000040))
		}
	}
	return p.bytes()
}

func TestParser_Parse_MissingRequiredSections(t *testing.T) {
	tests := []struct {
		name     string
		sections map[string]string
		wantMsg  string
	}{
		{"no kernel", map[string]string{".initrd": "I", ".cmdline": "c"}, "UKI missing required .linux section"},
		{"no initramfs", map[string]string{".linux": "K", ".cmdline": "c"}, "UKI missing required .initrd section"},
		{"no cmdline", map[string]string{".linux": "K", ".initrd": "I"}, "UKI missing required .cmdline section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewParser(testLogger(t)).Parse(bytes.NewReader(buildWithSections(t, tt.sections)))
			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Equal(t, tt.wantMsg, msgErr.Msg)
		})
	}
}

// TestParser_InputErrors covers the shared read and PE-parse failures of
// every parser entry point.
func TestParser_InputErrors(t *testing.T) {
	p := NewParser(testLogger(t))
	entries := map[string]func(io.Reader) error{
		"Parse": func(r io.Reader) error { _, err := p.Parse(r); return err },
		"ExtractSection": func(r io.Reader) error {
			_, err := p.ExtractSection(r, ".linux")
			return err
		},
		"ListSections": func(r io.Reader) error { _, err := p.ListSections(r); return err },
	}
	for name, call := range entries {
		t.Run(name+"/read", func(t *testing.T) {
			err := call(failingReader{})
			require.ErrorIs(t, err, errTestRead)
			assert.Contains(t, err.Error(), "failed to read UKI")
		})
		t.Run(name+"/invalid PE", func(t *testing.T) {
			err := call(strings.NewReader("not a PE"))
			var wrapped *WrappedError
			require.ErrorAs(t, err, &wrapped)
			assert.Equal(t, "invalid PE file", wrapped.Msg)
		})
	}
}

func TestParser_ExtractSection_NotFound(t *testing.T) {
	data := buildWithSections(t, map[string]string{".linux": "K"})
	_, err := NewParser(testLogger(t)).ExtractSection(bytes.NewReader(data), ".initrd")
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Equal(t, "section not found: .initrd", msgErr.Msg)
}

func TestParser_ParseFile_Missing(t *testing.T) {
	_, err := NewParser(testLogger(t)).ParseFile(filepath.Join(t.TempDir(), "missing.efi"))
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, err.Error(), "failed to open file")
}

// fakeObjcopy writes a shell script standing in for objcopy: it records its
// arguments and copies the input file (second-to-last argument) to the output
// file (last argument), or exits non-zero when fail is set.
func fakeObjcopy(t *testing.T, fail bool) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "objcopy")
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\n"
	if fail {
		script += "echo objcopy-boom >&2\nexit 3\n"
	} else {
		script += "for a; do in=$out; out=$a; done\ncp \"$in\" \"$out\"\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(script), 0o700))
	return path, argsFile
}

func newTestObjcopyBuilder(t *testing.T, objcopyPath string) *objcopyBuilder {
	t.Helper()
	b := NewObjcopyBuilder(testLogger(t)).(*objcopyBuilder)
	b.objcopyPath = objcopyPath
	return b
}

func TestObjcopyBuilder_Build_PassesSectionsInBootOrder(t *testing.T) {
	path, argsFile := fakeObjcopy(t, false)
	b := newTestObjcopyBuilder(t, path)
	require.NoError(t, b.AddSection(".custom", []byte("CUSTOM")))

	var out bytes.Buffer
	require.NoError(t, b.Build(fullUKI(), &out))
	// The fake objcopy copies its input, the kernel, to the output.
	assert.Equal(t, "KERNEL", out.String())

	recorded, err := os.ReadFile(argsFile)
	require.NoError(t, err)
	var order []string
	for _, arg := range strings.Split(string(recorded), "\n") {
		// Each section's --change-section-vma value is "<name>=0".
		if strings.HasPrefix(arg, ".") && strings.HasSuffix(arg, "=0") {
			order = append(order, strings.TrimSuffix(arg, "=0"))
		}
	}
	assert.Equal(t,
		[]string{".osrel", ".cmdline", ".ucode", ".splash", ".initrd", ".dtb", ".sbat", ".custom"},
		order)
}

func TestObjcopyBuilder_Build_Errors(t *testing.T) {
	okPath, _ := fakeObjcopy(t, false)
	tests := []struct {
		name    string
		mutate  func(u *UKI)
		output  io.Writer
		wantMsg string
	}{
		{"kernel read", func(u *UKI) { u.Kernel = failingReader{} }, nil, "failed to read kernel"},
		{"initramfs read", func(u *UKI) { u.Initramfs = failingReader{} }, nil, "failed to read initramfs"},
		{"microcode read", func(u *UKI) { u.Microcode = failingReader{} }, nil, "failed to read microcode"},
		{"splash read", func(u *UKI) { u.Splash = failingReader{} }, nil, "failed to read splash"},
		{"device tree read", func(u *UKI) { u.DeviceTree = failingReader{} }, nil, "failed to read device tree"},
		{"output write", func(u *UKI) {}, failingWriter{}, "failed to write UKI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := fullUKI()
			tt.mutate(u)
			out := tt.output
			if out == nil {
				out = &bytes.Buffer{}
			}
			err := newTestObjcopyBuilder(t, okPath).Build(u, out)
			require.ErrorIs(t, err, errTestRead)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

func TestObjcopyBuilder_Build_CommandFails(t *testing.T) {
	path, _ := fakeObjcopy(t, true)
	err := newTestObjcopyBuilder(t, path).Build(fullUKI(), &bytes.Buffer{})
	var cmdErr *CommandOutputError
	require.ErrorAs(t, err, &cmdErr)
	assert.Equal(t, "objcopy failed", cmdErr.Msg)
	assert.Contains(t, cmdErr.Detail, "objcopy-boom")
}

func TestObjcopyBuilder_BuildFile(t *testing.T) {
	okPath, _ := fakeObjcopy(t, false)
	b := newTestObjcopyBuilder(t, okPath)
	path := filepath.Join(t.TempDir(), "uki.efi")

	require.NoError(t, b.BuildFile(fullUKI(), path))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "KERNEL", string(data))
}

func TestObjcopyBuilder_BuildFile_Errors(t *testing.T) {
	failPath, _ := fakeObjcopy(t, true)
	b := newTestObjcopyBuilder(t, failPath)

	t.Run("create fails", func(t *testing.T) {
		err := b.BuildFile(fullUKI(), filepath.Join(t.TempDir(), "missing-dir", "uki.efi"))
		require.ErrorIs(t, err, os.ErrNotExist)
		assert.Contains(t, err.Error(), "failed to create output file")
	})

	t.Run("build fails and removes the file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "uki.efi")
		err := b.BuildFile(fullUKI(), path)
		var cmdErr *CommandOutputError
		require.ErrorAs(t, err, &cmdErr)
		_, statErr := os.Stat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}
