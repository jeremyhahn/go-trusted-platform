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

package ipxe

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSigner appends a marker to whatever it signs and records the
// names it saw through the bytes.
type recordingSigner struct {
	err    error
	signed [][]byte
}

func (r *recordingSigner) Sign(in io.Reader, out io.Writer) error {
	if r.err != nil {
		return r.err
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	r.signed = append(r.signed, data)
	_, err = out.Write(append(append([]byte{}, data...), []byte("+SIGNED")...))
	return err
}

// TestTFTPServer_FirmwareSigner pins that EFI binaries are served signed
// when a signer is configured, that non-EFI firmware (the BIOS ROM) is
// served as loaded, that the cached upstream copy stays unsigned, and that
// a signing failure is a typed, fatal load error rather than an unsigned
// binary handed to a Secure Boot client.
func TestTFTPServer_FirmwareSigner(t *testing.T) {
	cache := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cache, FirmwareSNPOnlyAArch64), []byte("MZarm64"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cache, "undionly.kpxe"), []byte("ROM"), 0o644))

	t.Run("efi firmware is signed, the rom is not, the cache is untouched", func(t *testing.T) {
		signer := &recordingSigner{}
		cfg := DefaultServerConfig()
		cfg.FirmwareSigner = signer
		server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())

		require.NoError(t, server.loadFirmwareFile(FirmwareSNPOnlyAArch64, "http://unused", cache))
		require.NoError(t, server.loadFirmwareFile("undionly.kpxe", "http://unused", cache))

		server.firmwareMu.RLock()
		defer server.firmwareMu.RUnlock()
		assert.Equal(t, []byte("MZarm64+SIGNED"), server.firmware[FirmwareSNPOnlyAArch64])
		assert.Equal(t, []byte("ROM"), server.firmware["undionly.kpxe"])
		assert.Equal(t, [][]byte{[]byte("MZarm64")}, signer.signed, "exactly the EFI binary was signed")
		cached, err := os.ReadFile(filepath.Join(cache, FirmwareSNPOnlyAArch64))
		require.NoError(t, err)
		assert.Equal(t, []byte("MZarm64"), cached, "the upstream copy is what gets re-signed with another key")
	})

	t.Run("no signer serves the upstream binary", func(t *testing.T) {
		server := NewTFTPServer(DefaultServerConfig(), net.ParseIP("192.168.1.1"), logging.DefaultLogger())
		require.NoError(t, server.loadFirmwareFile(FirmwareSNPOnlyAArch64, "http://unused", cache))
		server.firmwareMu.RLock()
		defer server.firmwareMu.RUnlock()
		assert.Equal(t, []byte("MZarm64"), server.firmware[FirmwareSNPOnlyAArch64])
	})

	t.Run("a signing failure is fatal and typed", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.FirmwareSigner = &recordingSigner{err: errors.New("no key")}
		server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())

		err := server.loadFirmwareFile(FirmwareSNPOnlyAArch64, "http://unused", cache)

		var signErr *FirmwareSignError
		require.ErrorAs(t, err, &signErr)
		assert.Equal(t, FirmwareSNPOnlyAArch64, signErr.Filename)
		server.firmwareMu.RLock()
		defer server.firmwareMu.RUnlock()
		assert.NotContains(t, server.firmware, FirmwareSNPOnlyAArch64, "an unsigned binary is never served to a Secure Boot client")
	})
}

func TestDefaultBootFilenameByArch_AArch64(t *testing.T) {
	m := DefaultBootFilenameByArch()
	assert.Equal(t, FirmwareSNPOnlyAArch64, m[archEFIAArch64], "EFI AArch64 (RFC 4578) gets the arm64 iPXE")
	assert.Equal(t, FirmwareSNPOnlyAArch64, m[archUBootARM64], "a stock U-Boot's arch type gets the same binary")
	assert.Equal(t, "ipxe.efi", m[archEFIx64], "x86 is unchanged")
}

func TestEntriesForArchitecture(t *testing.T) {
	entries := []BootEntry{
		{Name: "x86", Architecture: ArchitectureX86_64},
		{Name: "arm", Architecture: ArchitectureARM64},
		{Name: "any"},
	}
	names := func(es []BootEntry) []string {
		out := make([]string, len(es))
		for i, e := range es {
			out[i] = e.Name
		}
		return out
	}
	assert.Equal(t, []string{"arm", "any"}, names(EntriesForArchitecture(entries, ArchitectureARM64)))
	assert.Equal(t, []string{"x86", "any"}, names(EntriesForArchitecture(entries, ArchitectureX86_64)))
	assert.Equal(t, []string{"x86", "any"}, names(EntriesForArchitecture(entries, ArchitectureI386)), "a legacy-BIOS client runs a 32-bit iPXE (buildarch i386) and boots the x86_64 kernel")
	assert.Equal(t, []string{"x86", "arm", "any"}, names(EntriesForArchitecture(entries, "")), "a client that did not say gets everything")
	assert.Empty(t, EntriesForArchitecture(nil, ArchitectureARM64))
}

func TestTFTPServer_FirmwareOverrides(t *testing.T) {
	cache := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(cache, FirmwareSNPOnlyAArch64), []byte("MZupstream"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(cache, "ipxe.efi"), []byte("MZx64"), 0o644))
	local := filepath.Join(t.TempDir(), "snponly.efi")
	require.NoError(t, os.WriteFile(local, []byte("MZlocal"), 0o644))

	t.Run("an override is served, signed, ahead of the cache", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.FirmwareDir = cache
		cfg.FirmwareOffline = true
		cfg.FirmwareSigner = &recordingSigner{}
		cfg.FirmwareOverrides = map[string]string{FirmwareSNPOnlyAArch64: local}
		server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())

		require.NoError(t, server.loadFirmware())

		server.firmwareMu.RLock()
		defer server.firmwareMu.RUnlock()
		assert.Equal(t, []byte("MZlocal+SIGNED"), server.firmware[FirmwareSNPOnlyAArch64], "the local build, signed, not the cached upstream")
		assert.Equal(t, []byte("MZx64+SIGNED"), server.firmware["ipxe.efi"], "the rest still comes from the cache")
	})

	t.Run("an unreadable override fails startup with a typed error", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.FirmwareDir = cache
		cfg.FirmwareOffline = true
		cfg.FirmwareOverrides = map[string]string{FirmwareSNPOnlyAArch64: filepath.Join(t.TempDir(), "missing.efi")}
		server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())

		err := server.loadFirmware()

		var overrideErr *FirmwareOverrideError
		require.ErrorAs(t, err, &overrideErr)
		assert.Equal(t, FirmwareSNPOnlyAArch64, overrideErr.Filename)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestClientArchitectures(t *testing.T) {
	assert.Equal(t, []string{ArchitectureX86_64, ArchitectureI386}, ClientArchitectures(ArchitectureX86_64))
	assert.Equal(t, []string{ArchitectureARM64}, ClientArchitectures(ArchitectureARM64))
	assert.Equal(t, []string{ArchitectureI386}, ClientArchitectures(ArchitectureI386))
}
