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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeNetbootMedia lays out a netboot media build with one Pi set, a TFTP
// tree and an arm64 iPXE, and returns its root.
func writeNetbootMedia(t *testing.T, index string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range []string{
		"media/aarch64-rpi/" + MediaSetDescriptor,
		"rpi-tftp/start4.elf",
		"firmware/snponly-aarch64.efi",
		NetbootMediaSums,
	} {
		p := filepath.Join(root, filepath.FromSlash(f))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(f), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, NetbootMediaIndex), []byte(index), 0o644))
	return root
}

const fullIndex = `media_sets: [aarch64-rpi]
tftp_tree: rpi-tftp
arm64_ipxe: firmware/snponly-aarch64.efi
`

func TestLoadNetbootMedia(t *testing.T) {
	media, err := LoadNetbootMedia(writeNetbootMedia(t, fullIndex))
	require.NoError(t, err)
	assert.Equal(t, &NetbootMedia{MediaSets: []string{"aarch64-rpi"}, TFTPTree: "rpi-tftp", ARM64IPXE: "firmware/snponly-aarch64.efi"}, media)
	assert.True(t, media.HasMediaSet("aarch64-rpi"))
	assert.False(t, media.HasMediaSet("aarch64-virt"))

	media, err = LoadNetbootMedia(writeNetbootMedia(t, "media_sets: [aarch64-rpi]\n"))
	require.NoError(t, err, "the Pi stage is optional in a build")
	assert.Empty(t, media.TFTPTree)
}

func TestLoadNetbootMedia_Rejections(t *testing.T) {
	for name, index := range map[string]string{
		"unknown key":       "media_dir: media\nmedia_sets: [aarch64-rpi]\n",
		"unknown set":       "media_sets: [aarch64-virt]\n",
		"escaping tree":     "tftp_tree: ../elsewhere\n",
		"absolute ipxe":     "arm64_ipxe: /etc/passwd\n",
		"missing tftp tree": "tftp_tree: rpi-tftp-absent\n",
		"unparseable":       "media_sets: [\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadNetbootMedia(writeNetbootMedia(t, index))
			var mediaErr ErrNetbootMedia
			require.ErrorAs(t, err, &mediaErr)
			assert.NotEmpty(t, mediaErr.Error())
		})
	}

	root := writeNetbootMedia(t, fullIndex)
	require.NoError(t, os.Remove(filepath.Join(root, NetbootMediaSums)))
	_, err := LoadNetbootMedia(root)
	var mediaErr ErrNetbootMedia
	require.ErrorAs(t, err, &mediaErr, "a build without checksums cannot be verified once staged")

	_, err = LoadNetbootMedia(t.TempDir())
	require.ErrorAs(t, err, &mediaErr, "no index")
}

func TestLoadNetbootMedia_HTTPBoot(t *testing.T) {
	root := writeNetbootMedia(t, "media_sets: [aarch64-rpi]\nhttp_boot: http-boot\n")
	for _, name := range []string{HTTPBootImage, HTTPBootSignature, HTTPBootPublicKey} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, "http-boot"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "http-boot", name), []byte(name), 0o644))
	}

	media, err := LoadNetbootMedia(root)
	require.NoError(t, err)
	assert.Equal(t, "http-boot", media.HTTPBoot)
	assert.Equal(t, "data/http-boot", media.HTTPBootPath(), "the EEPROM's HTTP_PATH: the data directory is served at /data")
	assert.Empty(t, (&NetbootMedia{}).HTTPBootPath())
}

func TestLoadNetbootMedia_HTTPBootRejections(t *testing.T) {
	for name, remove := range map[string]string{
		"no boot.img":   HTTPBootImage,
		"no boot.sig":   HTTPBootSignature,
		"no public key": HTTPBootPublicKey,
	} {
		t.Run(name, func(t *testing.T) {
			root := writeNetbootMedia(t, "media_sets: [aarch64-rpi]\nhttp_boot: http-boot\n")
			for _, f := range []string{HTTPBootImage, HTTPBootSignature, HTTPBootPublicKey} {
				if f == remove {
					continue
				}
				require.NoError(t, os.MkdirAll(filepath.Join(root, "http-boot"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(root, "http-boot", f), []byte(f), 0o644))
			}
			_, err := LoadNetbootMedia(root)
			var mediaErr ErrNetbootMedia
			require.ErrorAs(t, err, &mediaErr)
			assert.Contains(t, mediaErr.Error(), remove)
		})
	}

	_, err := LoadNetbootMedia(writeNetbootMedia(t, "media_sets: [aarch64-rpi]\nhttp_boot: ../elsewhere\n"))
	var mediaErr ErrNetbootMedia
	require.ErrorAs(t, err, &mediaErr, "the directory must be inside the build")
}
