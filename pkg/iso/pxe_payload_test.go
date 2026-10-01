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

package iso

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// payloadServer serves files by path, as a media set does.
func payloadServer(t *testing.T, files map[string][]byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[strings.TrimPrefix(r.URL.Path, "/set/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/set"
}

func sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// runPayload runs the autoinstall's fetch_install_payload — the exact shell
// the installer runs — against base, into a temporary CD.
func runPayload(t *testing.T, base string) (cdrom string, output string, err error) {
	t.Helper()
	cdrom = filepath.Join(t.TempDir(), "cdrom")
	script := "set -e\nlog() { echo \"LOG: $1\"; }\nerror() { echo \"ERROR: $1\" >&2; exit 1; }\n" +
		PXEPayloadFunction + "\nfetch_install_payload \"$1\" \"$2\"\n"
	out, err := exec.Command("sh", "-c", script, "sh", base, cdrom).CombinedOutput()
	return cdrom, string(out), err
}

func TestPXEPayloadFunction_RebuildsTheCD(t *testing.T) {
	platformctl := []byte("#!/bin/sh\necho platformctl\n")
	startElf := []byte("ELF4")
	dracut := tarGz(t, map[string]string{"90platformd/module-setup.sh": "install() { :; }\n"})
	list := strings.Join([]string{
		"# <sha256> <kind> <dest> <src>",
		sum(platformctl) + " file platformd-bin/platformctl cdrom/platformd-bin/platformctl",
		sum(startElf) + " file boot-firmware/start4.elf cdrom/boot-firmware/start4.elf",
		sum(dracut) + " tar dracut-platformd dracut-platformd.tar.gz",
		"",
	}, "\n")
	base := payloadServer(t, map[string][]byte{
		"payload.list":                    []byte(list),
		"cdrom/platformd-bin/platformctl": platformctl,
		"cdrom/boot-firmware/start4.elf":  startElf,
		"dracut-platformd.tar.gz":         dracut,
	})

	cdrom, out, err := runPayload(t, base)
	require.NoError(t, err, out)
	assert.Contains(t, out, "Install payload in place (3 entries)")
	info, err := os.Stat(filepath.Join(cdrom, "platformd-bin", "platformctl"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&0o111, "the installer's binaries are executable")
	data, err := os.ReadFile(filepath.Join(cdrom, "boot-firmware", "start4.elf"))
	require.NoError(t, err)
	assert.Equal(t, startElf, data, "the Pi's boot firmware lands where the installer reads it")
	_, err = os.Stat(filepath.Join(cdrom, "dracut-platformd", "90platformd", "module-setup.sh"))
	assert.NoError(t, err, "a tar entry is extracted into its destination")
	_, err = os.Stat(filepath.Join(cdrom, ".payload-complete"))
	assert.NoError(t, err)
}

func TestPXEPayloadFunction_FailsClosed(t *testing.T) {
	platformctl := []byte("platformctl")
	good := sum(platformctl) + " file platformd-bin/platformctl platformctl\n"
	cases := map[string]struct {
		files map[string][]byte
		want  string
	}{
		"no list":        {map[string][]byte{}, "cannot fetch"},
		"missing entry":  {map[string][]byte{"payload.list": []byte(good)}, "cannot fetch payload platformctl"},
		"corrupt entry":  {map[string][]byte{"payload.list": []byte(good), "platformctl": []byte("tampered")}, "does not match its digest"},
		"escaping entry": {map[string][]byte{"payload.list": []byte(sum(platformctl) + " file ../../etc/passwd platformctl\n"), "platformctl": platformctl}, "escapes the CD"},
		"unknown kind":   {map[string][]byte{"payload.list": []byte(sum(platformctl) + " zip platformd-bin/platformctl platformctl\n"), "platformctl": platformctl}, "unknown kind"},
		"malformed":      {map[string][]byte{"payload.list": []byte(sum(platformctl) + " file only-three\n")}, "malformed"},
		"no installer":   {map[string][]byte{"payload.list": []byte(sum(platformctl) + " file other/tool platformctl\n"), "platformctl": platformctl}, "no platformd-bin/platformctl"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cdrom, out, err := runPayload(t, payloadServer(t, tc.files))
			require.Error(t, err, out)
			assert.Contains(t, out, tc.want)
			_, statErr := os.Stat(filepath.Join(cdrom, ".payload-complete"))
			assert.True(t, os.IsNotExist(statErr), "a failed payload is never marked complete")
		})
	}
}

// runNodeConfig runs the autoinstall's stage_node_config — the exact shell
// the installer runs.
func runNodeConfig(t *testing.T, config, cdrom, ca string) (string, error) {
	t.Helper()
	script := "set -e\nlog() { echo \"LOG: $1\"; }\nerror() { echo \"ERROR: $1\" >&2; exit 1; }\n" +
		NodeConfigFunction + "\nstage_node_config \"$1\" \"$2\" \"$3\"\n"
	out, err := exec.Command("sh", "-c", script, "sh", config, cdrom, ca).CombinedOutput()
	return string(out), err
}

func TestNodeConfigFunction(t *testing.T) {
	rebuiltCD := func(t *testing.T) string {
		t.Helper()
		cdrom := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(cdrom, "configs"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(cdrom, "configs", "installer.yaml"), []byte("baked"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(cdrom, ".payload-complete"), nil, 0o644))
		return cdrom
	}
	node := filepath.Join(t.TempDir(), "platform-config.yaml")
	require.NoError(t, os.WriteFile(node, []byte("node"), 0o644))
	ca := filepath.Join(t.TempDir(), "ca-bundle.pem")
	require.NoError(t, os.WriteFile(ca, []byte("ca"), 0o644))

	t.Run("the node's config replaces the set's baked one", func(t *testing.T) {
		cdrom := rebuiltCD(t)
		out, err := runNodeConfig(t, node, cdrom, ca)
		require.NoError(t, err, out)
		got, err := os.ReadFile(filepath.Join(cdrom, "configs", "installer.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "node", string(got))
		got, err = os.ReadFile(filepath.Join(cdrom, "configs", "ca-bundle.pem"))
		require.NoError(t, err)
		assert.Equal(t, "ca", string(got))
	})

	t.Run("left alone: a real CD, no node config, or the baked config itself", func(t *testing.T) {
		realCD := rebuiltCD(t)
		require.NoError(t, os.Remove(filepath.Join(realCD, ".payload-complete")))
		for name, args := range map[string][2]string{
			"real CD":        {node, realCD},
			"no node config": {"", rebuiltCD(t)},
		} {
			out, err := runNodeConfig(t, args[0], args[1], ca)
			require.NoError(t, err, name+": "+out)
			got, err := os.ReadFile(filepath.Join(args[1], "configs", "installer.yaml"))
			require.NoError(t, err)
			assert.Equal(t, "baked", string(got), name)
		}
		cdrom := rebuiltCD(t)
		out, err := runNodeConfig(t, filepath.Join(cdrom, "configs", "installer.yaml"), cdrom, ca)
		require.NoError(t, err, out)
	})

	t.Run("a failed copy ends the install", func(t *testing.T) {
		out, err := runNodeConfig(t, filepath.Join(t.TempDir(), "absent.yaml"), rebuiltCD(t), ca)
		require.Error(t, err)
		assert.Contains(t, out, "cannot stage the node's platform config")
	})
}
