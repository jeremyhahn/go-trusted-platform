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
	"crypto"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/fatimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// HTTPBootDir is the directory of a netboot media build that holds the
// Raspberry Pi HTTP boot files (container.NetbootMedia.HTTPBoot).
const HTTPBootDir = container.HTTPBootDir

// HTTPBoot configures the signed boot.img a Raspberry Pi's bootloader EEPROM
// fetches over HTTP (BOOT_ORDER with the HTTP nibble, SIGNED_BOOT=1). The
// image is the Pi set's boot partition; boot.sig is signed by the fleet key,
// which stays in the platform KMS: the build sends the KMS a digest.
type HTTPBoot struct {
	// FleetKey is the kms:// reference of the fleet signing key, an RSA-2048
	// key (the only size the bootloader verifies). A reference to a key that
	// is not in the KMS is refused: the fleet key never exists as a file.
	FleetKey string
	// FleetCert is the platform CA's reference for the fleet key's
	// certificate, which carries its public key; empty uses the key's id.
	FleetCert string
	// Timestamp is boot.sig's ts line; zero is the time of the build. A
	// reproducible build passes its SOURCE_DATE_EPOCH.
	Timestamp time.Time
	// TargetSoC is the optional boot.sig target-soc line. Empty omits it,
	// which is the default for boot.img; set 2711 or 2712 only when the
	// operator explicitly wants the EEPROM to enforce a SoC family.
	TargetSoC string
}

// HTTPBootInputs are what StageHTTPBoot builds the HTTP boot files from.
type HTTPBootInputs struct {
	// BootTree is the boot partition's files (Stage's output), which become
	// the FAT ramdisk.
	BootTree string
	// TargetSoC is the optional boot.sig target-soc line (2711 or 2712).
	// Empty writes no target-soc line.
	TargetSoC string
	// Signer is the fleet key: a KMS-backed crypto.Signer in a real build.
	Signer crypto.Signer
	// Timestamp is boot.sig's ts line.
	Timestamp time.Time
}

// HTTPBootFiles describes what StageHTTPBoot wrote.
type HTTPBootFiles struct {
	// KeyHash is the SHA-256 of the fleet public key in the bootloader's
	// encoding: the OTP customer key hash an operator burns.
	KeyHash [rpibootsig.KeyHashSize]byte
	// ImageSize is boot.img's size in bytes.
	ImageSize int
}

// KeyHashHex is KeyHash as lowercase hex.
func (f *HTTPBootFiles) KeyHashHex() string { return hex.EncodeToString(f.KeyHash[:]) }

// StageHTTPBoot writes the HTTP boot files into dest (replaced): boot.img, the
// FAT16 ramdisk of in.BootTree; boot.sig, rpi-eeprom-digest's signature of it
// by in.Signer; and pubkey.bin, the fleet public key as the EEPROM carries it.
// Before returning it reads the files back and verifies them as the
// bootloader does (the key against its hash, the digest, the signature), so a
// KMS that signs with the wrong key or scheme fails the build and not the
// fleet.
func StageHTTPBoot(in HTTPBootInputs, dest string) (*HTTPBootFiles, error) {
	if _, ok := rpibootsig.SoCs[in.TargetSoC]; !ok && in.TargetSoC != "" {
		return nil, &HTTPBootError{Step: "target-soc", Err: &rpibootsig.TargetSoCError{SoC: in.TargetSoC}}
	}
	pub, err := rpibootsig.PublicKeyOf(in.Signer)
	if err != nil {
		return nil, &HTTPBootError{Step: "the fleet key", Err: err}
	}
	blob, err := rpibootsig.KeyBlob(pub)
	if err != nil {
		return nil, &HTTPBootError{Step: "the fleet key", Err: err}
	}
	image, err := fatimage.Build(os.DirFS(in.BootTree), fatimage.Options{})
	if err != nil {
		return nil, &HTTPBootError{Step: "building boot.img from " + in.BootTree, Err: err}
	}
	sig, err := rpibootsig.Sign(in.Signer, image, rpibootsig.SignOptions{Timestamp: in.Timestamp, TargetSoC: in.TargetSoC})
	if err != nil {
		return nil, &HTTPBootError{Step: "signing boot.img", Err: err}
	}

	keyHash, err := rpibootsig.KeyHash(pub)
	if err != nil {
		return nil, &HTTPBootError{Step: "the fleet key", Err: err}
	}
	if _, err := rpibootsig.Verify(sig, image, pub, keyHash); err != nil {
		return nil, &HTTPBootError{Step: "verifying boot.sig", Err: err}
	}

	if err := os.RemoveAll(dest); err != nil {
		return nil, &HTTPBootError{Step: "clearing " + dest, Err: err}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, &HTTPBootError{Step: "creating " + dest, Err: err}
	}
	for name, data := range map[string][]byte{
		container.HTTPBootImage:     image,
		container.HTTPBootSignature: sig,
		container.HTTPBootPublicKey: blob,
	} {
		if err := os.WriteFile(filepath.Join(dest, name), data, 0o644); err != nil {
			return nil, &HTTPBootError{Step: "writing " + name, Err: err}
		}
	}
	return &HTTPBootFiles{KeyHash: keyHash, ImageSize: len(image)}, nil
}

// VerifyHTTPBoot checks a staged HTTP boot directory the way the bootloader
// does, from the files alone: pubkey.bin must hash to keyHash (the OTP hash),
// and boot.sig must verify boot.img under it.
func VerifyHTTPBoot(dir string, keyHash [rpibootsig.KeyHashSize]byte) (*rpibootsig.Signature, error) {
	read := func(name string) ([]byte, error) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, &HTTPBootError{Step: "reading " + name, Err: err}
		}
		return data, nil
	}
	image, err := read(container.HTTPBootImage)
	if err != nil {
		return nil, err
	}
	sig, err := read(container.HTTPBootSignature)
	if err != nil {
		return nil, err
	}
	blob, err := read(container.HTTPBootPublicKey)
	if err != nil {
		return nil, err
	}
	pub, err := rpibootsig.ParseKeyBlob(blob)
	if err != nil {
		return nil, &HTTPBootError{Step: container.HTTPBootPublicKey, Err: err}
	}
	parsed, err := rpibootsig.Verify(sig, image, pub, keyHash)
	if err != nil {
		return nil, &HTTPBootError{Step: "verifying boot.sig", Err: err}
	}
	return parsed, nil
}

// resolveHTTPBoot checks the HTTP boot configuration against the sets it is
// built for: a Raspberry Pi set whose board has a bootloader EEPROM, a KMS
// fleet key, and a platform client to reach it through.
func (c *Config) resolveHTTPBoot() error {
	fail := func(err error) error {
		return &BuildError{Step: "configuration", Err: &HTTPBootError{Step: "http boot", Err: err}}
	}
	h := c.HTTPBoot
	if !hasSet(c.Sets, container.MediaSetRaspberryPi) {
		return fail(&NoPiSetError{})
	}
	model, err := rpi.LookupModel(c.Model)
	if err != nil {
		return fail(err)
	}
	if model.SoC == "" {
		return fail(&NoEEPROMError{Model: model.Name})
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.FleetKey)), "kms://") {
		return fail(&FleetKeyRefError{Ref: h.FleetKey})
	}
	if c.Build.KMSClients == nil {
		return fail(&MissingFileError{File: "a platform client to reach the KMS"})
	}
	return nil
}

func hasSet(sets []Set, name string) bool {
	for _, s := range sets {
		if s.Name == name {
			return true
		}
	}
	return false
}

// httpBootFiles stages the Pi's HTTP boot directory from its TFTP tree,
// signed by the fleet key held in the KMS. It returns the OTP key hash.
func (c *Config) httpBootFiles(ctx context.Context) (*HTTPBootFiles, error) {
	h := c.HTTPBoot
	clients, err := c.Build.KMSClients()
	if err != nil {
		return nil, &HTTPBootError{Step: "connecting to the platform", Err: err}
	}
	signer, _, err := secureboot.NewKMSSigner(ctx, clients.KMS, clients.CA, h.FleetKey, h.FleetCert)
	if err != nil {
		return nil, &HTTPBootError{Step: "the fleet key", Err: err}
	}
	if _, err := rpi.LookupModel(c.Model); err != nil {
		return nil, &HTTPBootError{Step: "model", Err: err}
	}
	ts := h.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return StageHTTPBoot(HTTPBootInputs{
		BootTree:  filepath.Join(c.OutputDir, TFTPTreeDir),
		TargetSoC: h.TargetSoC,
		Signer:    signer,
		Timestamp: ts,
	}, filepath.Join(c.OutputDir, HTTPBootDir))
}

// HTTPBootError is a failure building or verifying the HTTP boot files.
type HTTPBootError struct {
	Step string
	Err  error
}

func (e *HTTPBootError) Error() string {
	return "diskimage/netboot: http boot: " + e.Step + ": " + e.Err.Error()
}
func (e *HTTPBootError) Unwrap() error { return e.Err }

// NoPiSetError is an HTTP boot configuration for a build with no Raspberry Pi
// set, whose boot partition boot.img is.
type NoPiSetError struct{}

func (e *NoPiSetError) Error() string {
	return "the build has no " + container.MediaSetRaspberryPi + " set to make boot.img from"
}

// NoEEPROMError is a board whose boot ROM has no bootloader EEPROM: it cannot
// fetch or verify a signed boot.img.
type NoEEPROMError struct {
	Model string
}

func (e *NoEEPROMError) Error() string {
	return e.Model + " has no bootloader EEPROM: it cannot HTTP boot a signed boot.img (Raspberry Pi 4, 400, CM4, 5)"
}

// FleetKeyRefError is a fleet key reference that does not name a KMS key.
type FleetKeyRefError struct {
	Ref string
}

func (e *FleetKeyRefError) Error() string {
	return "the fleet key " + e.Ref + " is not a kms:// reference: the fleet key must be held in the platform KMS, never a file"
}
