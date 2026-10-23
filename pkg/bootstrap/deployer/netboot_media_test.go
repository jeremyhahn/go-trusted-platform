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

package deployer

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
)

// localHost is a deploy target that is a directory on this machine: its
// commands run in a real shell, its uploads are file copies.
type localHost struct {
	uploads []string
}

func (h *localHost) Run(ctx context.Context, command string) (string, error) {
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	return string(out), err
}

func (h *localHost) CopyFileStream(_ context.Context, localPath, remotePath string) error {
	h.uploads = append(h.uploads, remotePath)
	in, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(remotePath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// writeBuild writes a netboot media build with real checksums.
func writeBuild(t *testing.T, files map[string]string, index string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, container.NetbootMediaIndex), []byte(index), 0o644))
	out, err := exec.Command("sh", "-c", "cd "+shellQuote(root)+" && find . -type f ! -name SHA256SUMS | sed 's|^\\./||' | sort | xargs sha256sum > SHA256SUMS").CombinedOutput()
	require.NoError(t, err, string(out))
	return root
}

func piBuild(t *testing.T, kernel string) string {
	return writeBuild(t, map[string]string{
		"media/aarch64-rpi/" + container.MediaSetDescriptor: "name: aarch64-rpi\n",
		"media/aarch64-rpi/vmlinuz-rpi":                     kernel,
		"rpi-tftp/start4.elf":                               "ELF",
		"rpi-tftp/9ffefdef/config.txt":                      "kernel=kernel8.img\n",
		"firmware/snponly-aarch64.efi":                      "MZ",
	}, "media_sets: [aarch64-rpi]\ntftp_tree: rpi-tftp\narm64_ipxe: firmware/snponly-aarch64.efi\n")
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestStageNetbootMedia_UploadsVerifiesAndSkipsWhenCurrent(t *testing.T) {
	build := piBuild(t, "kernel v1")
	remote := t.TempDir()
	host := &localHost{}

	paths, err := stageNetbootMedia(t.Context(), host, build, remote, discard())
	require.NoError(t, err)
	assert.Equal(t, netbootMediaPaths{tftpDir: "/data/rpi-tftp", arm64IPXE: "/data/firmware/snponly-aarch64.efi"}, paths)
	data, err := os.ReadFile(filepath.Join(remote, "rpi-tftp", "9ffefdef", "config.txt"))
	require.NoError(t, err)
	assert.Equal(t, "kernel=kernel8.img\n", string(data), "the per-device directory is staged as built")
	require.NotEmpty(t, host.uploads)
	assert.True(t, strings.HasSuffix(host.uploads[len(host.uploads)-1], "/SHA256SUMS"), "the checksums go last")

	host.uploads = nil
	_, err = stageNetbootMedia(t.Context(), host, build, remote, discard())
	require.NoError(t, err)
	assert.Empty(t, host.uploads, "an unchanged build is not uploaded again")
}

func TestStageNetbootMedia_ReplacesAChangedBuildWholesale(t *testing.T) {
	remote := t.TempDir()
	host := &localHost{}
	_, err := stageNetbootMedia(t.Context(), host, piBuild(t, "kernel v1"), remote, discard())
	require.NoError(t, err)
	stale := filepath.Join(remote, "media", "aarch64-old", "vmlinuz")
	require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0o755))
	require.NoError(t, os.WriteFile(stale, []byte("old"), 0o644))
	keep := filepath.Join(remote, "vmlinuz")
	require.NoError(t, os.WriteFile(keep, []byte("x86 legacy installer"), 0o644))

	host.uploads = nil
	_, err = stageNetbootMedia(t.Context(), host, piBuild(t, "kernel v2"), remote, discard())
	require.NoError(t, err)
	assert.NotEmpty(t, host.uploads)
	data, err := os.ReadFile(filepath.Join(remote, "media", "aarch64-rpi", "vmlinuz-rpi"))
	require.NoError(t, err)
	assert.Equal(t, "kernel v2", string(data))
	_, err = os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "no set of an older build survives")
	_, err = os.Stat(keep)
	assert.NoError(t, err, "what the build does not own is left alone")
}

// TestStageNetbootMedia_ReplacesTheHTTPBootFiles: a boot.sig left from an
// older build next to a new boot.img would be served as the pair the EEPROM
// refuses, so the build owns its http-boot directory.
func TestStageNetbootMedia_ReplacesTheHTTPBootFiles(t *testing.T) {
	httpBoot := func(version string) string {
		return writeBuild(t, map[string]string{
			"media/aarch64-rpi/" + container.MediaSetDescriptor: "name: aarch64-rpi\n",
			"http-boot/boot.img":   "image " + version,
			"http-boot/boot.sig":   "sig " + version,
			"http-boot/pubkey.bin": "key",
		}, "media_sets: [aarch64-rpi]\nhttp_boot: http-boot\n")
	}
	remote := t.TempDir()
	host := &localHost{}
	_, err := stageNetbootMedia(t.Context(), host, httpBoot("v1"), remote, discard())
	require.NoError(t, err)
	stale := filepath.Join(remote, "http-boot", "boot.sig.old")
	require.NoError(t, os.WriteFile(stale, []byte("old"), 0o644))

	_, err = stageNetbootMedia(t.Context(), host, httpBoot("v2"), remote, discard())
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(remote, "http-boot", "boot.img"))
	require.NoError(t, err)
	assert.Equal(t, "image v2", string(data))
	_, err = os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "nothing of an older http-boot directory survives")
}

// TestStageNetbootMedia_RemovesHTTPBootWhenTheBuildDropsIt: a build without a
// fleet key has no signed HTTP boot image, so the directory an earlier signed
// build left must not stay served.
func TestStageNetbootMedia_RemovesHTTPBootWhenTheBuildDropsIt(t *testing.T) {
	signed := writeBuild(t, map[string]string{
		"media/aarch64-rpi/" + container.MediaSetDescriptor: "name: aarch64-rpi\n",
		"http-boot/boot.img":   "image",
		"http-boot/boot.sig":   "sig",
		"http-boot/pubkey.bin": "key",
	}, "media_sets: [aarch64-rpi]\nhttp_boot: http-boot\n")
	remote := t.TempDir()
	host := &localHost{}
	_, err := stageNetbootMedia(t.Context(), host, signed, remote, discard())
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(remote, "http-boot", "boot.img"))
	require.NoError(t, err)

	unsigned := writeBuild(t, map[string]string{
		"media/aarch64-rpi/" + container.MediaSetDescriptor: "name: aarch64-rpi\n",
	}, "media_sets: [aarch64-rpi]\n")
	_, err = stageNetbootMedia(t.Context(), host, unsigned, remote, discard())
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(remote, "http-boot"))
	assert.True(t, os.IsNotExist(err), "no signed image of an older build is left to be served")
}

// TestStageNetbootMedia_FileOutsideTheChecksumsIsReplaced: sha256sum -c only
// checks the files it lists, so a file nobody signed under a directory the
// build owns has to fail verification and be cleared.
func TestStageNetbootMedia_FileOutsideTheChecksumsIsReplaced(t *testing.T) {
	build := piBuild(t, "kernel v1")
	remote := t.TempDir()
	host := &localHost{}
	_, err := stageNetbootMedia(t.Context(), host, build, remote, discard())
	require.NoError(t, err)
	for _, extra := range []string{
		filepath.Join(remote, "http-boot", "boot.img"),
		filepath.Join(remote, "rpi-tftp", "9ffefdef", "extra.bin"),
		filepath.Join(remote, "media", "aarch64-rpi", "extra.bin"),
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(extra), 0o755))
		require.NoError(t, os.WriteFile(extra, []byte("unsigned"), 0o644))

		host.uploads = nil
		_, err = stageNetbootMedia(t.Context(), host, build, remote, discard())
		require.NoError(t, err)
		assert.NotEmpty(t, host.uploads, "%s is not in the checksums, so the copy is re-staged", extra)
		_, err = os.Stat(extra)
		assert.True(t, os.IsNotExist(err), "%s is gone", extra)
	}
}

func TestStageNetbootMedia_TamperedCopyIsReplaced(t *testing.T) {
	build := piBuild(t, "kernel v1")
	remote := t.TempDir()
	host := &localHost{}
	_, err := stageNetbootMedia(t.Context(), host, build, remote, discard())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(remote, "firmware", "snponly-aarch64.efi"), []byte("not signed"), 0o644))

	host.uploads = nil
	_, err = stageNetbootMedia(t.Context(), host, build, remote, discard())
	require.NoError(t, err)
	assert.NotEmpty(t, host.uploads, "a file that no longer matches its checksum is re-staged")
	data, err := os.ReadFile(filepath.Join(remote, "firmware", "snponly-aarch64.efi"))
	require.NoError(t, err)
	assert.Equal(t, "MZ", string(data))
}

func TestStageNetbootMedia_Failures(t *testing.T) {
	var stageErr ErrNetbootMediaStage
	_, err := stageNetbootMedia(t.Context(), &localHost{}, t.TempDir(), t.TempDir(), discard())
	require.ErrorAs(t, err, &stageErr, "a directory that is not a build")
	assert.Equal(t, "reading the build", stageErr.Step)

	build := piBuild(t, "kernel v1")
	require.NoError(t, os.WriteFile(filepath.Join(build, "media", "aarch64-rpi", "vmlinuz-rpi"), []byte("changed after the sums"), 0o644))
	_, err = stageNetbootMedia(t.Context(), &localHost{}, build, t.TempDir(), discard())
	require.ErrorAs(t, err, &stageErr, "a build that does not match its own checksums is not staged as good")
	assert.Equal(t, "verifying the staged copy", stageErr.Step)
}
