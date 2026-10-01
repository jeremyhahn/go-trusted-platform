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

package bootstrap

import (
	"path/filepath"

	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"

	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// Node platforms. The empty platform is a generic server: x86_64, booted
// by its firmware's PXE ROM or by virtual media, with no model, serial or
// boot model.
const (
	PlatformGeneric     = ""
	PlatformRaspberryPi = "raspberrypi"
)

// Node architectures, spelled as the platform's media are (uki and the
// installer canonicalise to these).
const (
	ArchitectureX86_64  = "x86_64"
	ArchitectureAArch64 = "aarch64"
)

// Boot models for a Raspberry Pi. BootModelSD installs to the SD card over
// the network once (the bootloader tries the card first — BOOT_ORDER
// 0xf21 — so an installed node never asks the boot server again). The
// diskless models are added with their implementations.
const (
	BootModelSD = "sd"
)

// validPlatforms, validArchitectures and validPiBootModels are the accepted
// values; validation reports them in its errors.
var (
	validPlatforms     = []string{PlatformRaspberryPi}
	validArchitectures = []string{ArchitectureX86_64, ArchitectureAArch64}
	validPiBootModels  = []string{BootModelSD}
)

// EffectiveArchitecture is the node's architecture with its default: a
// Raspberry Pi is aarch64, anything else x86_64.
func (n *NodeConfig) EffectiveArchitecture() string {
	switch {
	case n.Architecture != "":
		return n.Architecture
	case n.Platform == PlatformRaspberryPi:
		return ArchitectureAArch64
	default:
		return ArchitectureX86_64
	}
}

// EffectiveBootModel is the node's boot model with its default: sd for a
// Raspberry Pi, none for a generic server.
func (n *NodeConfig) EffectiveBootModel() string {
	if n.BootModel == "" && n.Platform == PlatformRaspberryPi {
		return BootModelSD
	}
	return n.BootModel
}

// IsRaspberryPi reports whether the node is a Raspberry Pi.
func (n *NodeConfig) IsRaspberryPi() bool {
	return n.Platform == PlatformRaspberryPi
}

// PiSerial parses the node's serial as the Raspberry Pi bootloader sends
// it (up to eight hex digits); ok is false when none is configured.
func (n *NodeConfig) PiSerial() (serial uint32, ok bool) {
	if n.Serial == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(n.Serial), "0x"), 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// MediaSet names the media set the node boots, or empty for its
// architecture's default.
func (n *NodeConfig) MediaSet() string {
	if n.IsRaspberryPi() {
		return container.MediaSetRaspberryPi
	}
	return ""
}

// IPXEArchitecture is the node's architecture as iPXE reports it
// (${buildarch}): arm64 for aarch64, x86_64 otherwise.
func (n *NodeConfig) IPXEArchitecture() string {
	if n.EffectiveArchitecture() == ArchitectureAArch64 {
		return ipxe.ArchitectureARM64
	}
	return ipxe.ArchitectureX86_64
}

// validateNetbootMedia: the bootstrap container serves every installer it
// boots from the deployer's netboot media build, so the deployer needs one, and the build must carry what each PXE-installed node boots — the Pi
// set for a Pi, its architecture's default set for any other node, and for
// a Pi the TFTP tree and arm64 iPXE its bootloader and U-Boot fetch.
// Checked against the build on disk before anything is deployed.
func (c *BootstrapConfig) validateNetbootMedia() error {
	if c.Deployer.NetbootMediaDir == "" {
		return ErrNetbootMediaRequired{Reason: "deployer.netboot_media_dir is not set (build one with make netboot-media)"}
	}
	media, err := container.LoadNetbootMedia(c.Deployer.NetbootMediaDir)
	if err != nil {
		return ErrNetbootMediaRequired{Reason: "the build cannot be used", Err: err}
	}
	sets, err := container.LoadMediaSets(filepath.Join(c.Deployer.NetbootMediaDir, container.NetbootMediaSetsDir), "")
	if err != nil {
		return ErrNetbootMediaRequired{Reason: "the build's media sets cannot be used", Err: err}
	}
	defaults := map[string]bool{}
	for _, s := range sets {
		if s.Default {
			defaults[s.Architecture] = true
		}
	}
	for i := range c.Nodes {
		n := &c.Nodes[i]
		if n.SkipInstall || n.EffectiveBootMethod() != BootMethodPXE {
			continue
		}
		switch {
		case n.MediaSet() != "" && !media.HasMediaSet(n.MediaSet()):
			return ErrNetbootMediaRequired{Hostname: n.Hostname, Reason: "the build has no media set " + n.MediaSet()}
		case n.MediaSet() == "" && !defaults[n.IPXEArchitecture()]:
			return ErrNetbootMediaRequired{Hostname: n.Hostname, Reason: "the build has no default " + n.IPXEArchitecture() + " media set"}
		case n.IsRaspberryPi() && (media.TFTPTree == "" || media.ARM64IPXE == ""):
			return ErrNetbootMediaRequired{Hostname: n.Hostname, Reason: "the build has no Raspberry Pi TFTP tree or arm64 iPXE"}
		}
	}
	return nil
}

// ErrNetbootMediaRequired is a deployer without a usable netboot media
// build, or a node (Hostname) that boots media the build does not provide.
type ErrNetbootMediaRequired struct {
	Hostname string
	Reason   string
	Err      error
}

func (e ErrNetbootMediaRequired) Error() string {
	msg := "bootstrap: netboot media: " + e.Reason
	if e.Hostname != "" {
		msg = "bootstrap: node " + e.Hostname + " boots netboot media: " + e.Reason
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e ErrNetbootMediaRequired) Unwrap() error { return e.Err }

// validatePlatform checks the platform fields against each other and
// against how the node is provisioned.
func (n *NodeConfig) validatePlatform() error {
	if n.Architecture != "" && !slices.Contains(validArchitectures, n.Architecture) {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "architecture", Value: n.Architecture, Reason: "expected one of " + strings.Join(validArchitectures, ", ")}
	}
	switch n.Platform {
	case PlatformGeneric:
		for _, f := range []struct{ field, value string }{{"model", n.Model}, {"serial", n.Serial}, {"boot_model", n.BootModel}} {
			if f.value != "" {
				return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: f.field, Value: f.value, Reason: "only a node with a platform (" + strings.Join(validPlatforms, ", ") + ") takes " + f.field}
			}
		}
		return nil
	case PlatformRaspberryPi:
		return n.validateRaspberryPi()
	default:
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "platform", Value: n.Platform, Reason: "expected one of " + strings.Join(validPlatforms, ", ")}
	}
}

// validateRaspberryPi: a Pi has a model the netboot protocol knows, is
// aarch64, has no BMC (it is provisioned observe-only, over PXE — which
// also rules out virtual media, as that needs a BMC), and
// its serial — when given, for its per-device boot directory — is what
// the bootloader sends.
func (n *NodeConfig) validateRaspberryPi() error {
	if n.Model == "" {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "model", Reason: "required for platform raspberrypi (one of " + strings.Join(rpinetboot.Models(), ", ") + ")"}
	}
	if _, err := rpinetboot.LookupModel(n.Model); err != nil {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "model", Value: n.Model, Reason: "expected one of " + strings.Join(rpinetboot.Models(), ", ")}
	}
	if n.EffectiveArchitecture() != ArchitectureAArch64 {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "architecture", Value: n.Architecture, Reason: "a Raspberry Pi is aarch64"}
	}
	if n.BootModel != "" && !slices.Contains(validPiBootModels, n.BootModel) {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "boot_model", Value: n.BootModel, Reason: "expected one of " + strings.Join(validPiBootModels, ", ")}
	}
	if n.BMCAddress != "" {
		return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "bmc_address", Value: n.BMCAddress, Reason: "a Raspberry Pi has no BMC; it is provisioned over PXE and observed"}
	}
	if n.Serial != "" {
		if _, ok := n.PiSerial(); !ok {
			return ErrInvalidNodePlatform{Hostname: n.Hostname, Field: "serial", Value: n.Serial, Reason: "up to eight hex digits, as in /proc/cpuinfo's Serial (low 32 bits)"}
		}
	}
	return nil
}

// ErrInvalidNodePlatform is returned when a node's platform fields
// (platform, model, architecture, serial, boot_model) are invalid or
// inconsistent with how the node is provisioned.
type ErrInvalidNodePlatform struct {
	Hostname string
	Field    string
	Value    string
	Reason   string
}

func (e ErrInvalidNodePlatform) Error() string {
	if e.Value == "" {
		return fmt.Sprintf("bootstrap: node %s: %s: %s", e.Hostname, e.Field, e.Reason)
	}
	return fmt.Sprintf("bootstrap: node %s: %s %q: %s", e.Hostname, e.Field, e.Value, e.Reason)
}
