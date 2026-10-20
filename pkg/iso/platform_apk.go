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
	"bufio"
	"compress/gzip"
	"encoding/base64"
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

// ErrPlatformAPKDirUnusable reports a build that names PlatformAPKDir but
// whose media could not install the packages. They exist only in the media's
// offline repository, which only pre-fetch builds, and only an install
// configuration the media embeds names them.
type ErrPlatformAPKDirUnusable struct {
	// Reason says which part of the build rules the packages out.
	Reason string
}

func (e *ErrPlatformAPKDirUnusable) Error() string {
	return "platform-apk-dir cannot be used " + e.Reason
}

// ValidatePlatformAPKDir refuses a PlatformAPKDir the media could not
// install from: without pre-fetch the node looks for the packages on the
// Alpine mirror, which has none of them, and media that fetches its install
// configuration from a config server installs what the server's
// configuration names, which is not these packages.
func (c *ISOBuildConfig) ValidatePlatformAPKDir() error {
	if c.PlatformAPKDir == "" {
		return nil
	}
	if !c.PreFetch {
		return &ErrPlatformAPKDirUnusable{Reason: "without pre-fetch: the packages are in no Alpine mirror, only in the media's offline repository"}
	}
	if fetchesInstallConfig(c.ConfigServerURL, c.PlatformConfigFile) {
		return &ErrPlatformAPKDirUnusable{Reason: "with a config server and no platform config: the node installs what the server's configuration names, not these packages"}
	}
	return nil
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
// copies it rather than fetching it. Each apk must match its entry
// (verifyPlatformAPK): one that does not would be left out of the media's
// index, and the install would fail on the node.
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
		if err := verifyPlatformAPK(entry); err != nil {
			return err
		}
		b.packageIndex[name] = entry
	}
	b.logger.Info("[PREFETCH] Platform-built packages loaded", "dir", dir, "packages", len(platformBuiltPackages))
	return nil
}

// copyLocalPackage copies a platform-built apk to the prefetch directory.
// ErrPlatformAPKInvalid reports a platform-built apk that does not match its
// entry in the builder's APKINDEX, or cannot be indexed: truncated, corrupt,
// or from another build. The media build fails rather than producing media
// whose index lacks a package its install asks for.
type ErrPlatformAPKInvalid struct {
	// Path is the apk.
	Path string
	// Reason says what does not match.
	Reason string
	Err    error
}

func (e *ErrPlatformAPKInvalid) Error() string {
	msg := fmt.Sprintf("platform apk %s %s (make strongswan-build)", e.Path, e.Reason)
	if e.Err != nil {
		return msg + ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrPlatformAPKInvalid) Unwrap() error { return e.Err }

// ErrAPKNoControlSegment reports an apk none of whose gzip streams holds a
// .PKGINFO.
type ErrAPKNoControlSegment struct{}

func (ErrAPKNoControlSegment) Error() string { return "no gzip stream holds a .PKGINFO" }

// verifyPlatformAPK checks a platform-built apk against its APKINDEX entry:
// its size (S:), every gzip stream decompressing whole (gzip checks each
// stream's CRC-32 and length), and the checksum of its control segment (C:,
// "Q1" and the base64 SHA-1 of the gzip stream holding .PKGINFO, which apk
// itself checks at install).
func verifyPlatformAPK(entry *apkPackageEntry) error {
	// A FIPS build cannot compute C: and refuses before reading anything.
	hasher, err := newAPKChecksumHasher()
	if err != nil {
		return err
	}
	f, err := os.Open(entry.LocalPath)
	if err != nil {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: "cannot be read", Err: err}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: "cannot be read", Err: err}
	}
	if info.Size() != entry.Size {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: fmt.Sprintf("is %d bytes, its index entry %d", info.Size(), entry.Size)}
	}
	control, err := apkControlSegment(f)
	if err != nil {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: "is not a well-formed apk", Err: err}
	}
	if _, err := io.Copy(hasher, control); err != nil {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: "cannot be read", Err: err}
	}
	if sum := "Q1" + base64.StdEncoding.EncodeToString(hasher.Sum(nil)); sum != entry.Checksum {
		return &ErrPlatformAPKInvalid{Path: entry.LocalPath, Reason: fmt.Sprintf("has control checksum %s, its index entry %s", sum, entry.Checksum)}
	}
	return nil
}

// apkControlSegment decompresses every gzip stream of an apk (its signature,
// control and data segments) and returns the raw bytes of the first stream
// whose tar starts with .PKGINFO.
func apkControlSegment(f *os.File) (*io.SectionReader, error) {
	// gzip reads a reader that is also an io.ByteReader without buffering
	// ahead, so the count is exact at the end of every stream.
	in := &byteCounter{r: bufio.NewReader(f)}
	zr, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}
	var control *io.SectionReader
	var start int64
	for {
		zr.Multistream(false)
		hdr, err := tar.NewReader(zr).Next()
		if err != nil && err != io.EOF {
			return nil, err
		}
		if _, err := io.Copy(io.Discard, zr); err != nil {
			return nil, err
		}
		if control == nil && hdr != nil && hdr.Name == ".PKGINFO" {
			control = io.NewSectionReader(f, start, in.n-start)
		}
		start = in.n
		if err := zr.Reset(in); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
	}
	if control == nil {
		return nil, ErrAPKNoControlSegment{}
	}
	return control, nil
}

// byteCounter counts the bytes read through it.
type byteCounter struct {
	r *bufio.Reader
	n int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *byteCounter) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// isPlatformAPK reports whether file is the apk of a platform-built package
// in the index, which must not be left out of the media's APKINDEX.
func (b *PreFetchBuilder) isPlatformAPK(file string) bool {
	for _, name := range platformBuiltPackages {
		if entry, ok := b.packageIndex[name]; ok && entry.LocalPath != "" && filepath.Base(entry.LocalPath) == filepath.Base(file) {
			return true
		}
	}
	return false
}

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
