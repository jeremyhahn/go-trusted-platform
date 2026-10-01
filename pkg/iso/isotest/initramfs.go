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

// Package isotest holds test fixtures for the install media: an Alpine
// netboot initramfs shaped like the release's, and a reader for the
// initramfs the media build writes back.
package isotest

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// AlpineInit is the part of Alpine's mkinitfs /init the installer patches
// touch: configure_ip()'s DHCP block and the setup_inittab_console call.
const AlpineInit = `#!/bin/sh
configure_ip() {
	if [ "$ip" = dhcp ]; then
		$MOCK ip link set dev "$iface" up
		$MOCK udhcpc -i "$iface" -f -q
	fi
}
setup_inittab_console
exec switch_root "$sysroot" /sbin/init
`

// NetbootInitramfs is a gzip-compressed newc initramfs laid out like an
// Alpine netboot release's: /init (AlpineInit) and udhcpc's default.script.
func NetbootInitramfs() ([]byte, error) {
	return Initramfs(map[string]string{
		"init":                            AlpineInit,
		"usr/share/udhcpc/default.script": "#!/bin/sh\n",
	})
}

// Initramfs is a gzip-compressed newc initramfs of files (regular, mode
// 0755, root's), by path.
func Initramfs(files map[string]string) ([]byte, error) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	if err := writeNewc(gz, files); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return archive.Bytes(), nil
}

// ReadInitramfs is the regular files of the zstd-compressed newc initramfs
// at path (what the media build repacks), by path. It fails the test on any
// entry not owned by root.
func ReadInitramfs(t testing.TB, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	dec, err := zstd.NewReader(f)
	require.NoError(t, err)
	defer dec.Close()
	data, err := io.ReadAll(dec)
	require.NoError(t, err)
	return parseNewc(t, data)
}

// newc header: magic, then thirteen 8-digit hex fields.
const (
	newcMagic      = "070701"
	newcHeaderSize = 110
	newcTrailer    = "TRAILER!!!"
	newcRegular    = 0o100000
)

// writeNewc writes files (all regular, mode 0755, root's) as a newc archive.
func writeNewc(w io.Writer, files map[string]string) error {
	ino := 1
	entry := func(name string, mode int, body string) error {
		header := fmt.Sprintf("%s%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			newcMagic, ino, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name)+1, 0)
		ino++
		_, err := io.WriteString(w, header+name+"\x00"+pad(newcHeaderSize+len(name)+1)+body+pad(len(body)))
		return err
	}
	for name, body := range files {
		if err := entry(name, newcRegular|0o755, body); err != nil {
			return err
		}
	}
	return entry(newcTrailer, 0, "")
}

// parseNewc reads a newc archive's regular files.
func parseNewc(t testing.TB, data []byte) map[string]string {
	t.Helper()
	files := map[string]string{}
	for off := 0; ; {
		require.GreaterOrEqual(t, len(data)-off, newcHeaderSize, "truncated newc header")
		header := string(data[off : off+newcHeaderSize])
		require.Equal(t, newcMagic, header[:6], "not a newc archive")
		field := func(i int) int {
			v, err := strconv.ParseUint(header[6+8*i:14+8*i], 16, 32)
			require.NoError(t, err)
			return int(v)
		}
		mode, size, nameSize := field(1), field(6), field(11)
		nameStart := off + newcHeaderSize
		name := string(data[nameStart : nameStart+nameSize-1])
		if name == newcTrailer {
			return files
		}
		require.Zero(t, field(2), "%s is not owned by root", name)
		require.Zero(t, field(3), "%s is not in root's group", name)
		bodyStart := nameStart + nameSize + len(pad(newcHeaderSize+nameSize))
		if mode&0o170000 == newcRegular {
			files[strings.TrimPrefix(name, "./")] = string(data[bodyStart : bodyStart+size])
		}
		off = bodyStart + size + len(pad(size))
	}
}

// pad is the NUL padding that aligns n bytes to four.
func pad(n int) string {
	return string(make([]byte, (4-n%4)%4))
}
