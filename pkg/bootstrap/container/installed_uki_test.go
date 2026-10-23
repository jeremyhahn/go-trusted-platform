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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/nbd/nbdtest"
)

const (
	// nbdNodeMAC is nbd-01 in nbdManifest, an x86_64 node by default.
	nbdNodeMAC = "dc:a6:32:01:36:c2"
	// diskNodeMAC is cp-01 in nbdManifest, a disk node.
	diskNodeMAC = "aa:bb:cc:dd:ee:01"
)

func newNBDContainer(t *testing.T) *Server {
	t.Helper()
	// Never started: the address is only what the script names.
	config, _ := nbdStartConfig(t, "127.0.0.1:10809")
	server, err := NewServer(config, testLogger())
	require.NoError(t, err)
	return server
}

// writeExport writes identity's export volume, <volume_dir>/<identity>.img,
// as the NBD server keeps it.
func writeExport(t *testing.T, server *Server, identity string, content []byte) {
	t.Helper()
	dir := server.config.NBD.VolumeDir
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, identity+".img"), content, 0o600))
}

// installedExport is an x86_64 node's export after a diskless-nbd install.
func installedExport(t *testing.T, uki []byte) []byte {
	t.Helper()
	return nbdtest.BuildImage(t, 512, nbdtest.InstalledTree("BOOTX64.EFI", uki)).Bytes
}

// blankExport is a new export the NBD server created and no install wrote.
func blankExport(*testing.T) []byte {
	return make([]byte, 4<<20)
}

// brokenExport is partitioned, so an install began, but holds no UKI.
func brokenExport(t *testing.T) []byte {
	t.Helper()
	return nbdtest.BuildImage(t, 512, []nbdtest.Node{{Name: "EFI", Short: "EFI        ", Children: []nbdtest.Node{}}}).Bytes
}

func installedUKI(t *testing.T, server *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	server.deviceScriptMux().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestDeviceBootScript_InstalledDisklessNBDNodeBootsItsUKI(t *testing.T) {
	server := newNBDContainer(t)
	writeExport(t, server, "nbd-01", installedExport(t, []byte("signed uki")))

	status, script := deviceScript(t, server, "/boot/device/"+nbdNodeMAC+".ipxe")

	require.Equal(t, http.StatusOK, status)
	ukiURL := "http://" + server.deviceScriptAddr() + "/boot/uki/" + nbdNodeMAC + ".efi"
	assert.Contains(t, script, "kernel "+ukiURL+" || goto boot_failed\n")
	assert.NotContains(t, script, "initrd ")
	assert.NotContains(t, script, "platform_nbd_server", "the UKI's signed command line carries the server")
}

func TestDeviceBootScript_DisklessNBDNodeInstallsUntilItsExportHoldsAnInstall(t *testing.T) {
	for name, export := range map[string]func(*testing.T) []byte{
		"no export yet":                nil,
		"an attached but blank export": blankExport,
	} {
		t.Run(name, func(t *testing.T) {
			server := newNBDContainer(t)
			if export != nil {
				writeExport(t, server, "nbd-01", export(t))
			}

			status, script := deviceScript(t, server, "/boot/device/"+nbdNodeMAC+".ipxe")

			require.Equal(t, http.StatusOK, status)
			assert.Contains(t, script, "initrd ")
			assert.Contains(t, script, "platform_boot_model=diskless-nbd")
			assert.NotContains(t, script, "/boot/uki/")
		})
	}
}

// TestDeviceBootScript_BrokenExportIsNeverReinstalled: an export that is
// partitioned but unreadable fails the script rather than handing the node
// the installer, which would format the export over whatever it holds.
func TestDeviceBootScript_BrokenExportIsNeverReinstalled(t *testing.T) {
	server := newNBDContainer(t)
	writeExport(t, server, "nbd-01", brokenExport(t))

	status, script := deviceScript(t, server, "/boot/device/"+nbdNodeMAC+".ipxe")

	assert.Equal(t, http.StatusInternalServerError, status)
	assert.NotContains(t, script, "initrd ")
}

func TestHandleInstalledUKI_ServesTheInstalledUKI(t *testing.T) {
	server := newNBDContainer(t)
	uki := bytes.Repeat([]byte("signed uki "), 300)
	writeExport(t, server, "nbd-01", installedExport(t, uki))

	w := installedUKI(t, server, "/boot/uki/"+nbdNodeMAC+".efi")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, uki, w.Body.Bytes())
	assert.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, strconv.Itoa(len(uki)), w.Header().Get("Content-Length"))
}

func TestHandleInstalledUKI_Refused(t *testing.T) {
	for name, tc := range map[string]struct {
		path   string
		export func(*testing.T) []byte
		status int
	}{
		"malformed MAC":           {path: "/boot/uki/nbd-01.efi", status: http.StatusBadRequest},
		"MAC not in the manifest": {path: "/boot/uki/02:00:00:00:00:99.efi", status: http.StatusNotFound},
		"a disk node":             {path: "/boot/uki/" + diskNodeMAC + ".efi", status: http.StatusNotFound},
		"no export yet":           {path: "/boot/uki/" + nbdNodeMAC + ".efi", status: http.StatusNotFound},
		"a blank export":          {path: "/boot/uki/" + nbdNodeMAC + ".efi", export: blankExport, status: http.StatusNotFound},
		"a broken export":         {path: "/boot/uki/" + nbdNodeMAC + ".efi", export: brokenExport, status: http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			server := newNBDContainer(t)
			if tc.export != nil {
				writeExport(t, server, "nbd-01", tc.export(t))
			}

			w := installedUKI(t, server, tc.path)

			assert.Equal(t, tc.status, w.Code)
			assert.NotEqual(t, "application/octet-stream", w.Header().Get("Content-Type"))
		})
	}
}

func TestDeviceScriptMux_RoutesTheDeviceScript(t *testing.T) {
	server := newNBDContainer(t)
	w := installedUKI(t, server, "/boot/device/"+diskNodeMAC+".ipxe")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "#!ipxe")
}

func TestErrNotDisklessNBD(t *testing.T) {
	assert.Equal(t,
		"bootstrap container: aa:bb:cc:dd:ee:01 boots disk, not diskless-nbd, and has no installed UKI to serve",
		ErrNotDisklessNBD{MAC: diskNodeMAC}.Error())
	assert.Contains(t, ErrNotDisklessNBD{MAC: diskNodeMAC, BootModel: "diskless"}.Error(), "boots diskless, not")
}
