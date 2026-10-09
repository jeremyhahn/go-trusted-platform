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
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// platformBuiltPackages are the apks build/docker/strongswan-builder produces
// for the overlay's IPsec transport: charon and swanctl with their OpenRC
// service, and the glibc p11-kit module host with its OpenRC service. They
// exist nowhere on an Alpine mirror, so the media takes them from the
// builder's output (ISOBuildConfig.PlatformAPKDir).
var platformBuiltPackages = []string{
	"trusted-platform-strongswan",
	"trusted-platform-strongswan-openrc",
	"trusted-platform-p11-host",
	"trusted-platform-p11-host-openrc",
}

// platformMirrorPackages are the packages the platform-built ones need from
// the Alpine mirror and that the media lists by name rather than leaving to
// dependency resolution: p11-kit-server carries p11-kit-client.so, the PKCS#11
// module charon loads, and the platform-built apks depend on p11-kit-server
// at 0.26 or newer.
var platformMirrorPackages = []string{"p11-kit-server"}

// PlatformPackages returns every package an install medium built with
// ISOBuildConfig.PlatformAPKDir carries and installs for the overlay's IPsec
// transport.
func PlatformPackages() []string {
	packages := make([]string, 0, len(platformBuiltPackages)+len(platformMirrorPackages))
	packages = append(packages, platformBuiltPackages...)
	return append(packages, platformMirrorPackages...)
}

// installPackages returns the packages the installer installs beyond its own
// set: the configured extras and, when the media carries the platform-built
// apks, the overlay IPsec packages.
func (o InstallerOverrides) installPackages() []string {
	packages := append([]string(nil), o.ExtraPackages...)
	if o.PlatformAPKDir != "" {
		packages = append(packages, PlatformPackages()...)
	}
	return packages
}

// ErrPlatformAPKMissing reports a platform-built apk the media must carry that
// the builder output does not provide. The media build fails rather than
// producing media that installs without charon: a node whose overlay cannot
// come up is only noticed in the field.
type ErrPlatformAPKMissing struct {
	// Dir is the architecture directory of the builder output that was read.
	Dir string
	// Package is the missing package, or the index file when it is missing.
	Package string
	Err     error
}

func (e *ErrPlatformAPKMissing) Error() string {
	msg := fmt.Sprintf("platform apk %s is missing from %s (make strongswan-build)", e.Package, e.Dir)
	if e.Err != nil {
		return msg + ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrPlatformAPKMissing) Unwrap() error { return e.Err }

// loadPlatformIndex adds the platform-built packages to the package index.
// The builder output holds one directory per Alpine architecture, each with
// the apks and their APKINDEX.tar.gz. Its entries replace any of the same
// name from the mirror, and each records the apk's path so the download step
// copies it rather than fetching it.
func (b *PreFetchBuilder) loadPlatformIndex() error {
	dir := filepath.Join(b.config.PlatformAPKDir, b.config.Architecture)
	indexPath := filepath.Join(dir, "APKINDEX.tar.gz")
	f, err := os.Open(indexPath)
	if err != nil {
		return &ErrPlatformAPKMissing{Dir: dir, Package: "APKINDEX.tar.gz", Err: err}
	}
	defer f.Close()

	built := &PreFetchBuilder{logger: b.logger, packageIndex: make(map[string]*apkPackageEntry)}
	if err := built.parseIndexArchive(f); err != nil {
		return &ErrPlatformAPKMissing{Dir: dir, Package: "APKINDEX.tar.gz", Err: err}
	}

	for _, name := range platformBuiltPackages {
		entry, ok := built.packageIndex[name]
		if !ok {
			return &ErrPlatformAPKMissing{Dir: dir, Package: name}
		}
		entry.LocalPath = filepath.Join(dir, fmt.Sprintf("%s-%s.apk", entry.Name, entry.Version))
		if _, err := os.Stat(entry.LocalPath); err != nil {
			return &ErrPlatformAPKMissing{Dir: dir, Package: name, Err: err}
		}
		b.packageIndex[name] = entry
	}
	b.logger.Info("[PREFETCH] Platform-built packages loaded", "dir", dir, "packages", len(platformBuiltPackages))
	return nil
}

// copyLocalPackage copies a platform-built apk to the prefetch directory.
func copyLocalPackage(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
