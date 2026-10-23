// Package disklessroot is the one definition of a diskless node's root image:
// the artifact names, the dm-verity parameters pinned at build and at open,
// the signed manifest that carries the root hash from the media build to the
// installer, and the kernel command line the signed UKI hands to
// platform-initrd.
//
// The package is a leaf (standard library only) because three very different
// binaries share it: the media pipeline that builds the image, the installer
// that writes the UKI, and the static initramfs binary that mounts the root.
package disklessroot

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// BootModel is the boot model of a node whose root is the diskless image.
const BootModel = "diskless"

// Artifact and manifest names. The squashfs and its hash tree sit in the media
// set's directory and are fetched over HTTP; the signed manifest sits in the
// install media under Dir, where the installer reads it.
const (
	Dir           = "diskless"
	RootFSFile    = "rootfs.squashfs"
	VerityFile    = "rootfs.verity"
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.json.sig"
)

// The dm-verity parameters. They are constants, not manifest fields: the hash
// tree is formatted without a superblock and opened with these values, so
// nothing fetched over the network chooses the algorithm, the block sizes or
// the number of data blocks.
const (
	HashAlgorithm = "sha256"
	BlockSize     = 4096
)

// ManifestVersion is the only manifest version this package reads and writes.
const ManifestVersion = 1

// saltDomain separates the verity salt from any other value derived from the
// same epoch and version.
const saltDomain = "go-trusted-platform diskless-root verity salt v1"

// ValidateRootHash reports whether hash is a dm-verity sha256 root hash in the
// canonical form veritysetup prints: 64 lowercase hex characters.
func ValidateRootHash(hash string) error {
	return validateHex(ParamRootHash, hash)
}

// ValidateSalt reports whether salt is a verity salt in the form DeriveSalt
// produces: 64 lowercase hex characters.
func ValidateSalt(salt string) error {
	return validateHex(ParamVeritySalt, salt)
}

// DeriveSalt returns the verity salt for a build: a sha256 over the build's
// SOURCE_DATE_EPOCH and version, so two builds of the same release produce the
// same hash tree and root hash.
func DeriveSalt(sourceDateEpoch int64, version string) string {
	sum := sha256.Sum256([]byte(saltDomain + "\x00" + strconv.FormatInt(sourceDateEpoch, 10) + "\x00" + version))
	return hex.EncodeToString(sum[:])
}

// validateHex accepts exactly 64 lowercase hex characters: a sha256 value.
func validateHex(field, value string) error {
	if len(value) != 2*sha256.Size {
		return &FieldError{Field: field, Reason: "must be 64 lowercase hex characters"}
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return &FieldError{Field: field, Reason: "must be 64 lowercase hex characters"}
		}
	}
	return nil
}

// FieldError reports an invalid or conflicting value for one manifest field
// or kernel command line parameter.
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string {
	return "disklessroot: " + e.Field + ": " + e.Reason
}

// ManifestError reports a manifest that could not be read, written or parsed.
type ManifestError struct {
	Path string
	Err  error
}

func (e *ManifestError) Error() string {
	return "disklessroot: manifest " + e.Path + ": " + e.Err.Error()
}

func (e *ManifestError) Unwrap() error {
	return e.Err
}

// SignatureError reports a manifest signature that could not be made or did
// not verify against the trust anchor.
type SignatureError struct {
	Reason string
	Err    error
}

func (e *SignatureError) Error() string {
	if e.Err == nil {
		return "disklessroot: signature: " + e.Reason
	}
	return "disklessroot: signature: " + e.Reason + ": " + e.Err.Error()
}

func (e *SignatureError) Unwrap() error {
	return e.Err
}
