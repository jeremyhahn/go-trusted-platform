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

// Package containertest writes netboot media builds for the tests of the
// packages that load one (the bootstrap config, the bootstrap CLI).
package containertest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
)

// WriteNetbootBuild writes into root a netboot media build
// (container.NetbootMedia) holding the named sets — the x86_64 set is its
// architecture's default, the first arm64 one is when defaultArm64 is set;
// each with stand-in kernel, initrd and modloop files and a payload that
// provides container.InstallerEntryPoint — and, with pi, the Raspberry Pi
// TFTP tree and arm64 iPXE.
func WriteNetbootBuild(root string, pi, defaultArm64 bool, sets ...string) error {
	write := func(rel, content string) error {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		return os.WriteFile(p, []byte(content), 0o644)
	}
	arm64Default := defaultArm64
	for _, set := range sets {
		arch, def := "arm64", false
		if set == container.MediaSetX86_64 {
			arch, def = "x86_64", true
		} else if arm64Default {
			def, arm64Default = true, false
		}
		if err := write("media/"+set+"/media-set.yaml", fmt.Sprintf("name: %s\narchitecture: %s\nkernel: k\ninitrd: i\nmodloop: m\ndefault: %t\n", set, arch, def)); err != nil {
			return err
		}
		for _, f := range []string{"k", "i", "m"} {
			if err := write("media/"+set+"/"+f, f); err != nil {
				return err
			}
		}
		// Every set carries the payload the installer runs.
		if err := write("media/"+set+"/cdrom/"+container.InstallerEntryPoint, "#!/bin/sh\n"); err != nil {
			return err
		}
		setDir := filepath.Join(root, "media", set)
		entries, err := container.PayloadFromTree(filepath.Join(setDir, "cdrom"), "cdrom")
		if err != nil {
			return err
		}
		list, err := os.Create(filepath.Join(setDir, container.PayloadListName))
		if err != nil {
			return err
		}
		if err := container.WritePayloadList(list, entries); err != nil {
			return errors.Join(err, list.Close())
		}
		if err := list.Close(); err != nil {
			return err
		}
	}
	index := "media_sets: [" + strings.Join(sets, ", ") + "]\n"
	if pi {
		if err := write("rpi-tftp/start4.elf", "ELF"); err != nil {
			return err
		}
		if err := write("firmware/snponly-aarch64.efi", "MZ"); err != nil {
			return err
		}
		index += "tftp_tree: rpi-tftp\narm64_ipxe: firmware/snponly-aarch64.efi\n"
	}
	if err := write("netboot-media.yaml", index); err != nil {
		return err
	}
	return write("SHA256SUMS", "")
}
