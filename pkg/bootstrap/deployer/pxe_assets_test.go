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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// repoRoot walks up from this package to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the deployer package")
	return ""
}

// TestPXEPayload_EveryFetchedBinaryIsAlsoServed pins the invariant #648 broke:
// a binary the autoinstall script fetches over platform_bin_url MUST be put
// into the container's /data by some serving path, or the fetch 404s and the
// install fails on the node that needed it.
//
// The fetch side lives in pkg/iso (buildAutoinstallScript's loop) and the
// serving side is spread across three files that no single package imports,
// which is exactly why the two drifted: adding gatewayd to the fetch list did
// not make any server produce it.
func TestPXEPayload_EveryFetchedBinaryIsAlsoServed(t *testing.T) {
	root := repoRoot(t)

	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err, "reading %s", rel)
		return string(b)
	}

	dockerfile := read("build/docker/bootstrap/Dockerfile")
	makefile := read("Makefile")

	// Binaries the autoinstall script fetches into /media/cdrom/platformd-bin.
	// Keep in sync with buildAutoinstallScript in pkg/iso/customize.go.
	for _, bin := range []string{"platformctl", "platformd", "platform-initrd", "gatewayd"} {
		t.Run(bin, func(t *testing.T) {
			// 1. The deployer stages it out of the image onto the host.
			require.Contains(t, pxeImageAssets, bin,
				"%s is fetched by the autoinstall script but stagePXEAssets never copies it "+
					"out of the container image, so it is absent from the host DataDir", bin)

			// 2. The image actually carries it under /data.
			servedDirectly := strings.Contains(dockerfile, "COPY "+bin+" /data/"+bin)
			servedViaOptional := strings.Contains(dockerfile, "COPY optional/ /data/")
			require.True(t, servedDirectly || servedViaOptional,
				"%s is fetched by the autoinstall script but the bootstrap Dockerfile "+
					"never COPYs it into /data, so /data/%s 404s", bin, bin)

			// 3. make pxeboot-extract produces it in the build context.
			require.True(t,
				strings.Contains(makefile, "platformd-bin/"+bin),
				"%s is fetched by the autoinstall script but pxeboot-extract never "+
					"extracts platformd-bin/%s from the ISO, so the build context lacks it", bin, bin)
		})
	}
}

// TestPXEPayload_GatewaydIsOptionalNotRequired guards the reason gatewayd is
// served out of optional/ rather than as a bare COPY: one container serves
// /data to every role, but an ISO only carries gatewayd when its bundled
// config enables the gateway role (pkg/iso/gatewayd.go). A required COPY
// would break the image build for every gateway-less deployment.
func TestPXEPayload_GatewaydIsOptionalNotRequired(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "build", "docker", "bootstrap", "Dockerfile"))
	require.NoError(t, err)
	dockerfile := string(b)

	require.False(t, strings.Contains(dockerfile, "COPY gatewayd /data/gatewayd"),
		"gatewayd must not be a required COPY: an ISO built from a non-gateway config "+
			"ships no gatewayd and the image build would fail for every such deployment")
	require.True(t, strings.Contains(dockerfile, "COPY optional/ /data/"),
		"gatewayd is served out of the always-present optional/ directory")
}
