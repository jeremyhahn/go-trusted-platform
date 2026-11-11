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

package uki

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUKIValidate(t *testing.T) {
	tests := []struct {
		name    string
		uki     *UKI
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid UKI",
			uki: &UKI{
				Kernel:    strings.NewReader("kernel data"),
				Initramfs: strings.NewReader("initramfs data"),
				Cmdline:   "root=/dev/sda1 ro quiet",
			},
			wantErr: false,
		},
		{
			name: "missing kernel",
			uki: &UKI{
				Initramfs: strings.NewReader("initramfs data"),
				Cmdline:   "root=/dev/sda1",
			},
			wantErr: true,
			errMsg:  "kernel is required",
		},
		{
			name: "missing initramfs",
			uki: &UKI{
				Kernel:  strings.NewReader("kernel data"),
				Cmdline: "root=/dev/sda1",
			},
			wantErr: true,
			errMsg:  "initramfs is required",
		},
		{
			name: "missing cmdline",
			uki: &UKI{
				Kernel:    strings.NewReader("kernel data"),
				Initramfs: strings.NewReader("initramfs data"),
			},
			wantErr: true,
			errMsg:  "kernel command line is required",
		},
		{
			name: "empty cmdline",
			uki: &UKI{
				Kernel:    strings.NewReader("kernel data"),
				Initramfs: strings.NewReader("initramfs data"),
				Cmdline:   "",
			},
			wantErr: true,
			errMsg:  "kernel command line is required",
		},
		{
			name: "valid with optional fields",
			uki: &UKI{
				Kernel:     strings.NewReader("kernel data"),
				Initramfs:  strings.NewReader("initramfs data"),
				Cmdline:    "root=/dev/sda1",
				OSRelease:  "NAME=TestOS\nVERSION=1.0",
				Stub:       strings.NewReader("stub data"),
				Microcode:  strings.NewReader("microcode data"),
				Splash:     strings.NewReader("splash data"),
				DeviceTree: strings.NewReader("device tree data"),
				SBAT:       "sbat,1,2025,Test Platform",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.uki.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFromFiles(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	kernelPath := filepath.Join(tmpDir, "vmlinuz")
	initramfsPath := filepath.Join(tmpDir, "initramfs.img")

	err := os.WriteFile(kernelPath, []byte("test kernel data"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(initramfsPath, []byte("test initramfs data"), 0644)
	require.NoError(t, err)

	tests := []struct {
		name          string
		kernelPath    string
		initramfsPath string
		cmdline       string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "valid files",
			kernelPath:    kernelPath,
			initramfsPath: initramfsPath,
			cmdline:       "root=/dev/sda1",
			wantErr:       false,
		},
		{
			name:          "missing kernel file",
			kernelPath:    filepath.Join(tmpDir, "nonexistent-kernel"),
			initramfsPath: initramfsPath,
			cmdline:       "root=/dev/sda1",
			wantErr:       true,
			errContains:   "failed to open kernel",
		},
		{
			name:          "missing initramfs file",
			kernelPath:    kernelPath,
			initramfsPath: filepath.Join(tmpDir, "nonexistent-initramfs"),
			cmdline:       "root=/dev/sda1",
			wantErr:       true,
			errContains:   "failed to open initramfs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uki, err := FromFiles(tt.kernelPath, tt.initramfsPath, tt.cmdline)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, uki)
			assert.NotNil(t, uki.Kernel)
			assert.NotNil(t, uki.Initramfs)
			assert.Equal(t, tt.cmdline, uki.Cmdline)

			// Clean up
			err = uki.Close()
			assert.NoError(t, err)
		})
	}
}

func TestUKIClose(t *testing.T) {
	tests := []struct {
		name    string
		uki     *UKI
		wantErr bool
	}{
		{
			name: "close readers with closers",
			uki: &UKI{
				Kernel:    &mockCloser{Reader: strings.NewReader("kernel")},
				Initramfs: &mockCloser{Reader: strings.NewReader("initramfs")},
				Stub:      &mockCloser{Reader: strings.NewReader("stub")},
				Microcode: &mockCloser{Reader: strings.NewReader("microcode")},
				Cmdline:   "test",
			},
			wantErr: false,
		},
		{
			name: "close readers without closers",
			uki: &UKI{
				Kernel:    strings.NewReader("kernel"),
				Initramfs: strings.NewReader("initramfs"),
				Cmdline:   "test",
			},
			wantErr: false,
		},
		{
			name: "close with error from kernel",
			uki: &UKI{
				Kernel:    &mockCloserWithError{Reader: strings.NewReader("kernel"), err: errors.New("kernel close error")},
				Initramfs: &mockCloser{Reader: strings.NewReader("initramfs")},
				Cmdline:   "test",
			},
			wantErr: true,
		},
		{
			name: "close with error from initramfs",
			uki: &UKI{
				Kernel:    &mockCloser{Reader: strings.NewReader("kernel")},
				Initramfs: &mockCloserWithError{Reader: strings.NewReader("initramfs"), err: errors.New("initramfs close error")},
				Cmdline:   "test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.uki.Close()

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDefaultStubPath(t *testing.T) {
	assert.Equal(t, "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", DefaultStubPath)
}

func TestSectionStruct(t *testing.T) {
	section := Section{
		Name: ".cmdline",
		Data: []byte("root=/dev/sda1"),
	}

	assert.Equal(t, ".cmdline", section.Name)
	assert.Equal(t, []byte("root=/dev/sda1"), section.Data)
}

func TestUKIStructFields(t *testing.T) {
	kernel := strings.NewReader("kernel data")
	initramfs := strings.NewReader("initramfs data")
	stub := strings.NewReader("stub data")
	microcode := strings.NewReader("microcode data")
	splash := strings.NewReader("splash data")
	deviceTree := strings.NewReader("device tree data")

	uki := &UKI{
		Kernel:     kernel,
		Initramfs:  initramfs,
		Cmdline:    "root=/dev/sda1 ro quiet",
		OSRelease:  "NAME=TestOS",
		Stub:       stub,
		Microcode:  microcode,
		Splash:     splash,
		DeviceTree: deviceTree,
		SBAT:       "sbat,1,2025,Test",
	}

	assert.NotNil(t, uki.Kernel)
	assert.NotNil(t, uki.Initramfs)
	assert.Equal(t, "root=/dev/sda1 ro quiet", uki.Cmdline)
	assert.Equal(t, "NAME=TestOS", uki.OSRelease)
	assert.NotNil(t, uki.Stub)
	assert.NotNil(t, uki.Microcode)
	assert.NotNil(t, uki.Splash)
	assert.NotNil(t, uki.DeviceTree)
	assert.Equal(t, "sbat,1,2025,Test", uki.SBAT)
}

func TestFromFilesWithRealFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	kernelData := []byte("This is test kernel data")
	initramfsData := []byte("This is test initramfs data")

	kernelPath := filepath.Join(tmpDir, "vmlinuz-test")
	initramfsPath := filepath.Join(tmpDir, "initramfs-test.img")

	err := os.WriteFile(kernelPath, kernelData, 0644)
	require.NoError(t, err)

	err = os.WriteFile(initramfsPath, initramfsData, 0644)
	require.NoError(t, err)

	cmdline := "root=/dev/sda1 ro quiet splash"

	uki, err := FromFiles(kernelPath, initramfsPath, cmdline)
	require.NoError(t, err)
	require.NotNil(t, uki)

	// Verify cmdline
	assert.Equal(t, cmdline, uki.Cmdline)

	// Verify kernel data can be read
	kernelRead, err := io.ReadAll(uki.Kernel)
	require.NoError(t, err)
	assert.Equal(t, kernelData, kernelRead)

	// Verify initramfs data can be read
	initramfsRead, err := io.ReadAll(uki.Initramfs)
	require.NoError(t, err)
	assert.Equal(t, initramfsData, initramfsRead)

	// Clean up
	err = uki.Close()
	assert.NoError(t, err)
}

func TestUKIValidateWithAllOptionalFields(t *testing.T) {
	uki := &UKI{
		Kernel:     strings.NewReader("kernel"),
		Initramfs:  strings.NewReader("initramfs"),
		Cmdline:    "root=/dev/sda1",
		OSRelease:  "NAME=TestOS\nVERSION=1.0\nID=testos",
		Stub:       strings.NewReader("stub"),
		Microcode:  strings.NewReader("microcode"),
		Splash:     strings.NewReader("splash"),
		DeviceTree: strings.NewReader("dtb"),
		SBAT:       "sbat,1,2025-12-19,Test Platform,https://example.com",
	}

	err := uki.Validate()
	require.NoError(t, err)
}

// Mock types for testing

type mockCloser struct {
	io.Reader
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

type mockCloserWithError struct {
	io.Reader
	err error
}

func (m *mockCloserWithError) Close() error {
	return m.err
}

func TestUKICloseMultipleErrors(t *testing.T) {
	uki := &UKI{
		Kernel:    &mockCloserWithError{Reader: strings.NewReader("kernel"), err: errors.New("kernel error")},
		Initramfs: &mockCloserWithError{Reader: strings.NewReader("initramfs"), err: errors.New("initramfs error")},
		Stub:      &mockCloserWithError{Reader: strings.NewReader("stub"), err: errors.New("stub error")},
		Microcode: &mockCloserWithError{Reader: strings.NewReader("microcode"), err: errors.New("microcode error")},
		Cmdline:   "test",
	}

	err := uki.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "errors closing UKI resources")
}

func TestUKIClosePartialErrors(t *testing.T) {
	kernel := &mockCloser{Reader: strings.NewReader("kernel")}
	stub := &mockCloser{Reader: strings.NewReader("stub")}
	uki := &UKI{
		Kernel:    kernel,
		Initramfs: &mockCloserWithError{Reader: strings.NewReader("initramfs"), err: errors.New("initramfs error")},
		Stub:      stub,
		Cmdline:   "test",
	}

	err := uki.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initramfs error")
	assert.True(t, kernel.closed, "kernel must be closed")
	assert.True(t, stub.closed, "a failed initramfs close must not skip the stub")
}

func TestUKIWithBytesReader(t *testing.T) {
	kernelData := []byte("kernel binary data")
	initramfsData := []byte("initramfs binary data")

	uki := &UKI{
		Kernel:    bytes.NewReader(kernelData),
		Initramfs: bytes.NewReader(initramfsData),
		Cmdline:   "root=/dev/sda1",
	}

	err := uki.Validate()
	require.NoError(t, err)

	// bytes.Reader doesn't implement Close, so this should succeed without errors
	err = uki.Close()
	require.NoError(t, err)
}
