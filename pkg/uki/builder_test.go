package uki

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	logger := testLogger(t)
	b := NewBuilder(logger)
	require.NotNil(t, b)

	impl, ok := b.(*builder)
	require.True(t, ok)
	assert.Equal(t, ArchX86_64, impl.arch)
	assert.Equal(t, DefaultStubPath, impl.stubPath)
	assert.Equal(t, 4096, impl.alignmentBytes)
	assert.Empty(t, impl.sections)
}

func TestBuilder_SetArchitecture(t *testing.T) {
	logger := testLogger(t)
	b := NewBuilder(logger)

	tests := []struct {
		name    string
		arch    string
		wantErr bool
	}{
		{name: "x86_64", arch: "x86_64", wantErr: false},
		{name: "aarch64", arch: "aarch64", wantErr: false},
		{name: "arm", arch: "arm", wantErr: false},
		{name: "riscv64", arch: "riscv64", wantErr: false},
		{name: "invalid", arch: "mips", wantErr: true},
		{name: "empty", arch: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.SetArchitecture(tt.arch)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported architecture")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBuilder_AddSection(t *testing.T) {
	logger := testLogger(t)
	b := NewBuilder(logger)

	t.Run("valid section", func(t *testing.T) {
		err := b.AddSection(".test", []byte("test data"))
		require.NoError(t, err)
	})

	t.Run("name too long", func(t *testing.T) {
		err := b.AddSection(".toolongname", []byte("data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "section name too long")
	})

	t.Run("max length name", func(t *testing.T) {
		err := b.AddSection("12345678", []byte("data"))
		require.NoError(t, err)
	})
}

func TestBuilder_Build_InvalidUKI(t *testing.T) {
	logger := testLogger(t)
	b := NewBuilder(logger)

	// Missing kernel
	uki := &UKI{
		Initramfs: strings.NewReader("initramfs"),
		Cmdline:   "root=/dev/sda1",
	}

	var buf strings.Builder
	err := b.Build(uki, &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid UKI configuration")
}

func TestObjcopyBuilder_SetArchitecture(t *testing.T) {
	logger := testLogger(t)
	b := NewObjcopyBuilder(logger)

	tests := []struct {
		name    string
		arch    string
		wantErr bool
	}{
		{name: "x86_64", arch: "x86_64", wantErr: false},
		{name: "aarch64", arch: "aarch64", wantErr: false},
		{name: "invalid", arch: "sparc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := b.SetArchitecture(tt.arch)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestObjcopyBuilder_AddSection(t *testing.T) {
	logger := testLogger(t)
	b := NewObjcopyBuilder(logger)

	t.Run("valid section", func(t *testing.T) {
		err := b.AddSection(".custom", []byte("custom data"))
		require.NoError(t, err)
	})

	t.Run("name too long", func(t *testing.T) {
		err := b.AddSection(".toolongname", []byte("data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "section name too long")
	})
}

func TestObjcopyBuilder_Build_InvalidUKI(t *testing.T) {
	logger := testLogger(t)
	b := NewObjcopyBuilder(logger)

	uki := &UKI{
		Kernel:  strings.NewReader("kernel"),
		Cmdline: "root=/dev/sda1",
		// Missing initramfs
	}

	var buf strings.Builder
	err := b.Build(uki, &buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid UKI configuration")
}
