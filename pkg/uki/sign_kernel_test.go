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
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// markingSigner "signs" by appending a marker, recording what it was given.
type markingSigner struct {
	in  []byte
	err error
}

func (m *markingSigner) SignFile(in, out string) error {
	if m.err != nil {
		return m.err
	}
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	m.in = data
	return os.WriteFile(out, append(data, []byte("+SIGNED")...), 0o644)
}

func TestSignKernel(t *testing.T) {
	dir := t.TempDir()
	pe := []byte("MZ kernel image")

	t.Run("a gzip vmlinuz is decompressed, then signed", func(t *testing.T) {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		_, err := w.Write(pe)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		src := filepath.Join(dir, "vmlinuz.gz")
		require.NoError(t, os.WriteFile(src, gz.Bytes(), 0o644))
		signer := &markingSigner{}
		dst := filepath.Join(dir, "vmlinuz.signed")

		require.NoError(t, SignKernel(src, dst, signer))
		assert.Equal(t, pe, signer.in, "the signer sees the PE image, not the gzip")
		out, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, append(append([]byte{}, pe...), []byte("+SIGNED")...), out)
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, e := range entries {
			assert.NotContains(t, e.Name(), ".unsigned", "the intermediate image is removed")
		}
	})

	t.Run("an uncompressed PE is signed as is", func(t *testing.T) {
		src := filepath.Join(dir, "vmlinuz-rpi")
		require.NoError(t, os.WriteFile(src, pe, 0o644))
		signer := &markingSigner{}
		require.NoError(t, SignKernel(src, filepath.Join(dir, "rpi.signed"), signer))
		assert.Equal(t, pe, signer.in)
	})

	t.Run("failures", func(t *testing.T) {
		src := filepath.Join(dir, "vmlinuz-rpi")
		err := SignKernel(src, filepath.Join(dir, "x"), &markingSigner{err: errors.New("no key")})
		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Contains(t, err.Error(), "signing the kernel")

		require.Error(t, SignKernel(filepath.Join(dir, "absent"), filepath.Join(dir, "y"), &markingSigner{}))
		require.Error(t, SignKernel(src, filepath.Join(dir, "no-such-dir", "z"), &markingSigner{}), "an unwritable destination")
	})
}
