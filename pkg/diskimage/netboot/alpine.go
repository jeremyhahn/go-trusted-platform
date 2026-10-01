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

package netboot

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

// alpineNetboot is Alpine's netboot release tarball for one architecture,
// pinned by the digest Alpine publishes beside it: the kernel, initramfs and
// modloop of every flavour a netboot media set boots.
type alpineNetboot struct {
	file   string
	sha256 string
}

// alpineNetboots are the pinned tarballs, by Alpine version and architecture.
var alpineNetboots = map[string]map[string]alpineNetboot{
	"3.22.2": {
		"aarch64": {file: "alpine-netboot-3.22.2-aarch64.tar.gz", sha256: "be57d346c814a109d89b68aad981e4b7086b42bb189f664dd042f6cba0419849"},
		"x86_64":  {file: "alpine-netboot-3.22.2-x86_64.tar.gz", sha256: "42ddf844d17c7eed833a1cafe52c446651b9cb5a6a28a32dbf37829231c17f4f"},
	},
}

// fetchAlpineNetboot returns the cached, digest-verified netboot tarball for
// version and arch, downloading it from mirror when the cache lacks it.
func fetchAlpineNetboot(ctx context.Context, version, arch, mirror, cacheDir string) (string, error) {
	pinned, ok := alpineNetboots[version][arch]
	if !ok {
		return "", &UnpinnedReleaseError{Version: version, Architecture: arch}
	}
	download := &iso.ISOConfig{
		Version:      version,
		ISO:          pinned.file,
		MirrorURL:    mirror,
		Architecture: arch,
		WorkDir:      cacheDir,
		SHA256:       pinned.sha256,
	}
	if err := iso.DownloadISO(ctx, download); err != nil {
		return "", &Error{Source: pinned.file, Err: err}
	}
	return download.ISOPath(), nil
}

// flavourFiles are a netboot flavour's kernel, initramfs and modloop.
type flavourFiles struct {
	Kernel, Initrd, Modloop string
}

// extractFlavour copies a flavour's kernel, initramfs and modloop out of the
// netboot tarball into dest.
func extractFlavour(tarball, flavour, dest string) (flavourFiles, error) {
	files := flavourFiles{Kernel: "vmlinuz-" + flavour, Initrd: "initramfs-" + flavour, Modloop: "modloop-" + flavour}
	wanted := map[string]bool{files.Kernel: true, files.Initrd: true, files.Modloop: true}
	if _, err := artifacts.ExtractTarGz(tarball, "boot/", dest, func(rel string) bool { return wanted[rel] }); err != nil {
		return flavourFiles{}, &Error{Source: tarball, Err: err}
	}
	for name := range wanted {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			return flavourFiles{}, &Error{Source: tarball, Err: &MissingFileError{File: name}}
		}
	}
	return files, nil
}
