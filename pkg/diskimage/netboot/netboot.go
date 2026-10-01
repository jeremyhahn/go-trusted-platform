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

// Package netboot stages the TFTP tree a Raspberry Pi network boot serves:
// the boot partition's firmware set, from the factory image or from the
// build inputs the image is made from. It lives with the image tooling it
// uses, apart from pkg/rpinetboot, so the PXE server — which only needs
// the protocol, and which the gateway daemon links — never carries it.
package netboot

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/runner"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/uboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// Inputs are the build inputs a TFTP tree is staged from: the same
// ones the factory image's boot partition is built from.
type Inputs struct {
	// Model is the board the config.txt is written for (rpi.LookupModel).
	Model string
	// PrefetchDir holds the raspberrypi-bootloader, -common and linux-rpi
	// apks (pkg/iso PreFetchBuilder.FetchPackages).
	PrefetchDir string
	// UBoot is the rpi_arm64 U-Boot build (uboot.Locate), served as
	// kernel8.img with its TPM overlay.
	UBoot uboot.Artifacts
}

// Stage fills dest with what a Raspberry Pi fetches over TFTP —
// start4.elf and fixup4.dat, every board device tree, the overlays,
// config.txt and U-Boot as kernel8.img — from the build inputs, exactly
// as the factory image's boot partition is staged. dest is replaced.
func Stage(ctx context.Context, in Inputs, dest string) error {
	target, err := rpi.New(in.Model)
	if err != nil {
		return &Error{Source: "model", Err: err}
	}
	if err := target.StageBootFirmwareInto(ctx, dest, in.PrefetchDir, in.UBoot); err != nil {
		return &Error{Source: "build inputs", Err: err}
	}
	return nil
}

// StageFromImage fills dest with the factory image's boot partition,
// less what only the SD card needs: the UKI under EFI/ (U-Boot netboots
// iPXE instead), the installer container under tpm2/, U-Boot's variable
// store and the provisioning marker. The result is what the boot server
// serves a Pi that would otherwise boot this image from its card. dest is
// replaced; run runs mtools (nil means the host's).
func StageFromImage(ctx context.Context, image, dest string, run runner.Runner) ([]string, error) {
	if err := os.RemoveAll(dest); err != nil {
		return nil, &Error{Source: image, Err: err}
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, &Error{Source: image, Err: err}
	}
	files, err := diskimage.ExtractESP(ctx, image, dest, keepForNetboot, run)
	if err != nil {
		return nil, &Error{Source: image, Err: err}
	}
	for _, required := range []string{"config.txt", rpinetboot.DefaultKernel} {
		if _, err := os.Stat(filepath.Join(dest, required)); err != nil {
			return nil, &Error{Source: image, Err: &MissingFileError{File: required}}
		}
	}
	return files, nil
}

// keepForNetboot selects the boot-partition files a network boot serves.
func keepForNetboot(name string) bool {
	switch {
	case strings.HasPrefix(name, "EFI/"), strings.HasPrefix(name, "tpm2/"):
		return false
	case name == "ubootefi.var":
		return false
	}
	return true
}

// Error is a failure staging the tree from the named source.
type Error struct {
	Source string
	Err    error
}

func (e *Error) Error() string { return "diskimage/netboot: from " + e.Source + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// MissingFileError names a file a Pi needs that the staged tree lacks.
type MissingFileError struct {
	File string
}

func (e *MissingFileError) Error() string { return "diskimage/netboot: no " + e.File }

// UnpinnedReleaseError is an Alpine release the build has no pinned netboot
// tarball for: every download is verified against a pinned digest.
type UnpinnedReleaseError struct {
	Version, Architecture string
}

func (e *UnpinnedReleaseError) Error() string {
	return "diskimage/netboot: no pinned Alpine " + e.Version + " netboot tarball for " + e.Architecture
}
