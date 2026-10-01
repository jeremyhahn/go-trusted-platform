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
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// NetbootMediaIndex is the file at the root of a netboot media build that
// says what the build holds. The deployer stages the build into the data
// directory as it is laid out and reads this index to configure the
// container; nothing is inferred from which files happen to exist.
const NetbootMediaIndex = "netboot-media.yaml"

// NetbootMediaSetsDir is the directory of a netboot media build — and of
// the data directory it is staged into — that holds its media sets; the
// container serves it as ServerConfig.MediaDir.
const NetbootMediaSetsDir = "media"

// NetbootMediaSums is the build's checksum file (sha256sum format, paths
// relative to the build root) — what the deployer verifies a staged copy
// against before deciding to upload again.
const NetbootMediaSums = "SHA256SUMS"

// NetbootMedia is a netboot media build: the media sets beyond the legacy
// x86_64 installer, and what a Raspberry Pi needs before its installer —
// the TFTP boot tree and the db-signed arm64 iPXE its U-Boot chains. Every
// path is relative to the build root, which the deployer copies to the
// container's data directory unchanged.
type NetbootMedia struct {
	// MediaSets names the sets under media/.
	MediaSets []string `yaml:"media_sets"`
	// TFTPTree is the Raspberry Pi boot tree, or empty.
	TFTPTree string `yaml:"tftp_tree,omitempty"`
	// ARM64IPXE is the db-signed arm64 iPXE served as snponly-aarch64.efi,
	// or empty.
	ARM64IPXE string `yaml:"arm64_ipxe,omitempty"`
}

// LoadNetbootMedia reads and checks a netboot media build's index: every
// path it names is inside the build and present, and every media set has
// its descriptor.
func LoadNetbootMedia(root string) (*NetbootMedia, error) {
	indexPath := filepath.Join(root, NetbootMediaIndex)
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, ErrNetbootMedia{Path: indexPath, Reason: "cannot read", Err: err}
	}
	var media NetbootMedia
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // a mistyped or obsolete key is an error, not ignored
	if err := decoder.Decode(&media); err != nil {
		return nil, ErrNetbootMedia{Path: indexPath, Reason: "cannot parse", Err: err}
	}
	check := func(field, rel string) error {
		clean := filepath.Clean(rel)
		if filepath.IsAbs(clean) || clean == "." || strings.HasPrefix(clean, "..") {
			return ErrNetbootMedia{Path: indexPath, Reason: field + " " + rel + " must be a path inside the build"}
		}
		if _, err := os.Stat(filepath.Join(root, clean)); err != nil {
			return ErrNetbootMedia{Path: indexPath, Reason: field + " " + rel + " is missing", Err: err}
		}
		return nil
	}
	for _, set := range media.MediaSets {
		if err := check("media set", filepath.Join(NetbootMediaSetsDir, set, MediaSetDescriptor)); err != nil {
			return nil, err
		}
	}
	for _, f := range []struct{ field, rel string }{{"tftp_tree", media.TFTPTree}, {"arm64_ipxe", media.ARM64IPXE}} {
		if f.rel == "" {
			continue
		}
		if err := check(f.field, f.rel); err != nil {
			return nil, err
		}
	}
	if err := check("checksums", NetbootMediaSums); err != nil {
		return nil, err
	}
	return &media, nil
}

// HasMediaSet reports whether the build carries the named set.
func (m *NetbootMedia) HasMediaSet(name string) bool {
	return slices.Contains(m.MediaSets, name)
}
