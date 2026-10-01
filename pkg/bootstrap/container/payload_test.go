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

package container

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestPayloadList_RoundTrip(t *testing.T) {
	entries := []PayloadEntry{
		{SHA256: digest, Kind: PayloadTar, Dest: "dracut-platformd", Src: "dracut-platformd.tar.gz"},
		{SHA256: digest, Kind: PayloadFile, Dest: "boot-firmware/start4.elf", Src: "cdrom/boot-firmware/start4.elf"},
	}
	var buf bytes.Buffer
	require.NoError(t, WritePayloadList(&buf, entries))
	assert.True(t, strings.HasPrefix(buf.String(), "#"), "a header says what the columns are")
	parsed, err := ParsePayloadList(&buf)
	require.NoError(t, err)
	assert.Equal(t, []PayloadEntry{entries[1], entries[0]}, parsed, "sorted by destination")
}

func TestParsePayloadList_Rejections(t *testing.T) {
	for name, line := range map[string]string{
		"three fields":   digest + " file platformctl",
		"short digest":   "abc file a b",
		"non-hex digest": strings.Repeat("z", 64) + " file a b",
		"unknown kind":   digest + " zip a b",
		"escaping dest":  digest + " file ../etc/passwd b",
		"absolute src":   digest + " file a /etc/passwd",
		"unclean path":   digest + " file a/./b c",
		"dot dest":       digest + " file . b",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParsePayloadList(strings.NewReader("# header\n\n" + line + "\n"))
			var listErr ErrPayloadList
			require.ErrorAs(t, err, &listErr)
			assert.Equal(t, 3, listErr.Line, "the line is named")
		})
	}
	_, err := ParsePayloadList(strings.NewReader(digest + " file a b\n" + digest + " file a c\n"))
	var listErr ErrPayloadList
	require.ErrorAs(t, err, &listErr, "one destination, one source")
	assert.Contains(t, listErr.Error(), "twice")

	require.Error(t, WritePayloadList(&bytes.Buffer{}, []PayloadEntry{{SHA256: digest, Kind: "zip", Dest: "a", Src: "b"}}), "the writer refuses what the parser would")
}

func TestPayloadFromTreeAndVerify(t *testing.T) {
	set := t.TempDir()
	cdrom := filepath.Join(set, "cdrom")
	for _, f := range []string{"platformd-bin/platformctl", "boot-firmware/overlays/tpm-soft-spi.dtbo"} {
		p := filepath.Join(cdrom, filepath.FromSlash(f))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(f), 0o644))
	}
	entries, err := PayloadFromTree(cdrom, "cdrom")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	byDest := map[string]PayloadEntry{}
	for _, e := range entries {
		byDest[e.Dest] = e
	}
	e := byDest["boot-firmware/overlays/tpm-soft-spi.dtbo"]
	assert.Equal(t, "cdrom/boot-firmware/overlays/tpm-soft-spi.dtbo", e.Src)
	assert.Equal(t, PayloadFile, e.Kind)
	want, err := artifacts.FileSHA256(filepath.Join(cdrom, "boot-firmware", "overlays", "tpm-soft-spi.dtbo"))
	require.NoError(t, err)
	assert.Equal(t, want, e.SHA256)

	require.NoError(t, VerifyPayload(set, entries))
	require.NoError(t, os.WriteFile(filepath.Join(cdrom, "platformd-bin", "platformctl"), []byte("tampered"), 0o644))
	var listErr ErrPayloadList
	require.ErrorAs(t, VerifyPayload(set, entries), &listErr)
	require.NoError(t, os.Remove(filepath.Join(cdrom, "platformd-bin", "platformctl")))
	require.ErrorAs(t, VerifyPayload(set, entries), &listErr)

	_, err = PayloadFromTree(filepath.Join(set, "absent"), "x")
	assert.Error(t, err)
}

func TestMediaSetPayload_MustProvideTheInstaller(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "minirootfs.tar.gz"), []byte("rootfs"), 0o644))
	sum, err := artifacts.FileSHA256(filepath.Join(dir, "minirootfs.tar.gz"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, PayloadListName), []byte(sum+" file alpine-minirootfs.tar.gz minirootfs.tar.gz\n"), 0o644))

	set := &MediaSet{dir: dir}
	err = set.loadPayload()
	var setErr ErrMediaSet
	require.ErrorAs(t, err, &setErr)
	assert.Contains(t, setErr.Error(), InstallerEntryPoint)
}
