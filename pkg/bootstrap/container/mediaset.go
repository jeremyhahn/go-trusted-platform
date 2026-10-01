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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// MediaSetDescriptor is the file that makes a directory under
// ServerConfig.MediaDir a media set. It is written when the set is built.
const MediaSetDescriptor = "media-set.yaml"

// The media sets the netboot build produces: the x86_64 installer (x86_64's
// default), the Raspberry Pi set, which a Pi node boots by name, and the
// generic arm64 set (the QEMU virt stand-in's kernel), arm64's default.
const (
	MediaSetX86_64      = "x86_64"
	MediaSetRaspberryPi = "aarch64-rpi"
	MediaSetARM64Virt   = "aarch64-virt"
)

// MediaSet is one bootable installer environment the container serves: a
// kernel, its initramfs and modloop, the platform binaries built for the
// same architecture, and — for a set that installs a Raspberry Pi — the
// boot firmware and packages its installer lays down. A node boots the set
// its manifest entry names, or its architecture's default.
type MediaSet struct {
	// Name identifies the set: its directory name, and what a manifest
	// entry names (x86_64, aarch64-rpi, aarch64-virt).
	Name string `yaml:"name"`
	// Architecture is the iPXE ${buildarch} the set runs on (x86_64,
	// arm64).
	Architecture string `yaml:"architecture"`
	// Kernel, Initrd and Modloop are file names in the set's directory.
	// The kernel of an arm64 set is db-signed when it was built: U-Boot
	// verifies it.
	Kernel  string `yaml:"kernel"`
	Initrd  string `yaml:"initrd"`
	Modloop string `yaml:"modloop"`
	// KernelArgs are the flavour's own arguments: the modules its
	// initramfs needs to reach the network and the consoles the board has.
	// The installer arguments every set shares are added by the container.
	KernelArgs string `yaml:"kernel_args"`
	// Default makes the set its architecture's choice for a machine that
	// is not in the manifest, or whose entry names no set.
	Default bool `yaml:"default"`

	// dir is the set's directory in the container; urlPath its path on
	// the HTTP server (under /data); payload its payload list, verified
	// against dir.
	dir     string
	urlPath string
	payload []PayloadEntry
}

// LoadMediaSets reads every media set under root: each directory holding
// a media-set.yaml. The set's name must be its directory's, its
// architecture one iPXE reports, and its kernel, initrd and modloop must
// be there. A missing root is an empty list: the container then serves
// the legacy set alone.
func LoadMediaSets(root, urlRoot string) ([]MediaSet, error) {
	dirs, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrMediaSet{Path: root, Reason: "cannot read the media directory", Err: err}
	}
	var sets []MediaSet
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		descriptor := filepath.Join(root, d.Name(), MediaSetDescriptor)
		data, err := os.ReadFile(descriptor)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, ErrMediaSet{Path: descriptor, Reason: "cannot read", Err: err}
		}
		var set MediaSet
		if err := yaml.Unmarshal(data, &set); err != nil {
			return nil, ErrMediaSet{Path: descriptor, Reason: "cannot parse", Err: err}
		}
		set.dir = filepath.Join(root, d.Name())
		set.urlPath = path.Join(urlRoot, d.Name())
		if err := set.validate(d.Name()); err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Name < sets[j].Name })
	return sets, nil
}

// validate checks a loaded set against its directory.
func (m *MediaSet) validate(dirName string) error {
	descriptor := filepath.Join(m.dir, MediaSetDescriptor)
	if m.Name != dirName {
		return ErrMediaSet{Path: descriptor, Reason: fmt.Sprintf("name %q is not its directory's (%q)", m.Name, dirName)}
	}
	switch m.Architecture {
	case ipxe.ArchitectureX86_64, ipxe.ArchitectureARM64:
	default:
		return ErrMediaSet{Path: descriptor, Reason: fmt.Sprintf("architecture %q is not %s or %s", m.Architecture, ipxe.ArchitectureX86_64, ipxe.ArchitectureARM64)}
	}
	return m.checkFiles()
}

// checkFiles verifies the set's kernel, initrd and modloop are in its
// directory, and loads its payload list.
func (m *MediaSet) checkFiles() error {
	descriptor := filepath.Join(m.dir, MediaSetDescriptor)
	for _, f := range []struct{ field, file string }{{"kernel", m.Kernel}, {"initrd", m.Initrd}, {"modloop", m.Modloop}} {
		if f.file == "" || strings.ContainsAny(f.file, "/\\") {
			return ErrMediaSet{Path: descriptor, Reason: fmt.Sprintf("%s must be a file name in the set's directory, got %q", f.field, f.file)}
		}
		if _, err := os.Stat(filepath.Join(m.dir, f.file)); err != nil {
			return ErrMediaSet{Path: descriptor, Reason: f.field + " " + f.file + " is missing", Err: err}
		}
	}
	return m.loadPayload()
}

// loadPayload reads the set's payload list and verifies every source is
// in the set with its digest: what an installer booted from the set will
// fetch is checked when the container starts, not when a node boots.
func (m *MediaSet) loadPayload() error {
	listPath := filepath.Join(m.dir, PayloadListName)
	f, err := os.Open(listPath)
	if err != nil {
		return ErrMediaSet{Path: listPath, Reason: "the set has no payload list", Err: err}
	}
	defer f.Close()
	entries, err := ParsePayloadList(f)
	if err != nil {
		return ErrMediaSet{Path: listPath, Reason: "unusable", Err: err}
	}
	if err := VerifyPayload(m.dir, entries); err != nil {
		return ErrMediaSet{Path: listPath, Reason: "does not match the set", Err: err}
	}
	if !slices.ContainsFunc(entries, func(e PayloadEntry) bool { return e.Dest == InstallerEntryPoint }) {
		return ErrMediaSet{Path: listPath, Reason: "provides no " + InstallerEntryPoint + ", which the installer runs"}
	}
	m.payload = entries
	return nil
}

// InstallerEntryPoint is the payload destination the autoinstall runs:
// every set's payload must provide it.
const InstallerEntryPoint = "platformd-bin/platformctl"

// mediaSets is the complete, validated list the container serves: every set
// under MediaDir. There is at least one, and each architecture has at most
// one default. Names are unique by construction: a set's name is its
// directory's (MediaSet.validate).
func mediaSets(config *ServerConfig) ([]MediaSet, error) {
	urlRoot, err := config.dataURLPath(config.MediaDir)
	if err != nil {
		return nil, ErrMediaSet{Path: config.MediaDir, Reason: "not under the data directory", Err: err}
	}
	sets, err := LoadMediaSets(config.MediaDir, urlRoot)
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, ErrMediaSet{Path: config.MediaDir, Reason: "holds no media set (stage a netboot media build: make netboot-media)"}
	}
	defaults := map[string]string{}
	for _, s := range sets {
		if !s.Default {
			continue
		}
		if other, ok := defaults[s.Architecture]; ok {
			return nil, ErrMediaSet{Path: config.MediaDir, Reason: fmt.Sprintf("media sets %s and %s are both the %s default", other, s.Name, s.Architecture)}
		}
		defaults[s.Architecture] = s.Name
	}
	return sets, nil
}

// url is the HTTP URL of a file in the set.
func (m *MediaSet) url(base, file string) string {
	return base + path.Join(m.urlPath, file)
}

// bootArgs are the set's kernel arguments: its flavour's own, then what
// every installer boot needs —
//   - alpine_start=autoinstall: run the platform's autoinstall instead of
//     dropping to a shell;
//   - ip=dhcp: bring the boot NIC up before the modloop fetch;
//   - modloop=: the kernel-modules squashfs, which a PXE-booted node
//     cannot find on a CD;
//   - alpine_repo=: the live root's package source (without it the live
//     system installs nothing and has no /sbin/init), and
//     platform_apk_mirror= the same mirror for the autoinstall;
//   - platform_config=: the per-MAC installer.yaml endpoint;
//   - platform_bin_url=: where the set's platform binaries are, for the
//     autoinstall to fetch;
//   - platform_debug / platform_debug_sink: the boot diagnostics sink.
func (m *MediaSet) bootArgs(config *ServerConfig) string {
	base := serverBaseURL(config)
	args := []string{
		m.KernelArgs,
		"alpine_start=autoinstall",
		"ip=dhcp",
		"modloop=" + m.url(base, m.Modloop),
		"alpine_repo=" + strings.TrimRight(config.APKMirror, "/") + "/" + alpineRepoBranch(config.AlpineVersion) + "/main",
		"platform_apk_mirror=" + config.APKMirror,
		"platform_config=" + base + "/config/mac",
		"platform_bin_url=" + base + m.urlPath,
		"platform_debug=1",
		"platform_debug_sink=" + serverHostPort(config),
	}
	return strings.Join(strings.Fields(strings.Join(args, " ")), " ")
}

// bootEntry is the set as the iPXE server's default for its architecture.
func (m *MediaSet) bootEntry(config *ServerConfig) ipxe.BootEntry {
	base := serverBaseURL(config)
	return ipxe.BootEntry{
		Name:         m.Name,
		Description:  "Bootstrap installer (" + m.Name + ")",
		Architecture: m.Architecture,
		Kernel:       m.url(base, m.Kernel),
		Initrd:       m.url(base, m.Initrd),
		Args:         m.bootArgs(config),
	}
}

// serverHostPort is the boot server's address as nodes reach it.
func serverHostPort(config *ServerConfig) string {
	return fmt.Sprintf("%s:%d", config.DHCPConfig.ServerIP, config.HTTPPort)
}

// serverBaseURL is the boot server's HTTP base URL as nodes reach it.
func serverBaseURL(config *ServerConfig) string {
	return "http://" + serverHostPort(config)
}
