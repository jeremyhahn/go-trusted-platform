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

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ima"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// luksUUIDPrefix starts the device-mapper uuid of every LUKS mapping
// cryptsetup opens ("CRYPT-LUKS1-…", "CRYPT-LUKS2-…").
const luksUUIDPrefix = "CRYPT-LUKS"

// maxStackDepth bounds the walk down a device-mapper stack (LVM on LUKS on
// RAID …); real stacks are a few levels deep.
const maxStackDepth = 8

// btrfsFSType is the mountinfo filesystem type of a btrfs mount, whose
// member devices are listed under /sys/fs/btrfs/<fsid>/devices/.
const btrfsFSType = "btrfs"

// HostPosture collects the posture report from the running host
// (docs/vpn/engineering.md §4). Every path is a field so tests point it at a
// directory tree instead of the host.
type HostPosture struct {
	EfivarsDir    string
	SecurityFSDir string
	MountInfoPath string
	SysfsDir      string
	OSReleasePath string
	AgentVersion  string
	// KernelRelease returns the running kernel's release.
	KernelRelease func() (string, error)
	Now           func() time.Time
}

// NewHostPosture returns the collector for this host.
func NewHostPosture(agentVersion string) *HostPosture {
	return &HostPosture{
		EfivarsDir:    uefi.EfivarsPath,
		SecurityFSDir: ima.DefaultSecurityFSPath,
		MountInfoPath: "/proc/self/mountinfo",
		SysfsDir:      "/sys",
		OSReleasePath: "/etc/os-release",
		AgentVersion:  agentVersion,
		KernelRelease: unameRelease,
		Now:           time.Now,
	}
}

// Collect reads every fact. A fact the host cannot have — no efivarfs on a
// BIOS boot, no securityfs — is reported as unavailable for the policy to
// judge; a fact that exists but cannot be read is an error, because a report
// that guessed would be a report the gateway cannot trust.
func (h *HostPosture) Collect(ctx context.Context) (*gwvpn.PostureReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	secureBoot, err := h.secureBoot()
	if err != nil {
		return nil, &ErrPostureFact{Fact: "secure_boot", Cause: err}
	}
	imaPosture, err := h.ima()
	if err != nil {
		return nil, &ErrPostureFact{Fact: "ima", Cause: err}
	}
	rootEncrypted, err := h.rootEncrypted()
	if err != nil {
		return nil, &ErrPostureFact{Fact: "fde", Cause: err}
	}
	osRelease, err := h.osRelease()
	if err != nil {
		return nil, &ErrPostureFact{Fact: "os_release", Cause: err}
	}
	kernel, err := h.KernelRelease()
	if err != nil {
		return nil, &ErrPostureFact{Fact: "kernel_release", Cause: err}
	}
	return &gwvpn.PostureReport{
		SecureBoot:    secureBoot,
		IMA:           imaPosture,
		FDE:           gwvpn.FDEPosture{RootEncrypted: rootEncrypted},
		AgentVersion:  h.AgentVersion,
		OSRelease:     osRelease,
		KernelRelease: kernel,
		CollectedAt:   h.Now().UTC(),
	}, nil
}

// secureBoot reads the firmware's Secure Boot state from efivarfs.
func (h *HostPosture) secureBoot() (gwvpn.SecureBootPosture, error) {
	status, err := uefi.ReadSecureBootStatusFromDir(h.EfivarsDir)
	if errors.Is(err, uefi.ErrEfivarsUnavailable) {
		return gwvpn.SecureBootPosture{}, nil
	}
	if err != nil {
		return gwvpn.SecureBootPosture{}, err
	}
	return gwvpn.SecureBootPosture{Available: true, Enabled: status.SecureBoot, SetupMode: status.SetupMode}, nil
}

// ima reads IMA's state and digests its runtime measurement log, so the
// gateway can tell two reports of the same log apart from two of different
// logs.
func (h *HostPosture) ima() (gwvpn.IMAPosture, error) {
	status, err := ima.NewReader(ima.WithSecurityFSPath(h.SecurityFSDir)).GetStatus()
	if errors.Is(err, ima.ErrSecurityFSNotMounted) {
		return gwvpn.IMAPosture{}, nil
	}
	if err != nil {
		return gwvpn.IMAPosture{}, err
	}
	posture := gwvpn.IMAPosture{Available: status.Available, Enabled: status.Enabled, PolicyLoaded: status.PolicyLoaded}
	if !status.Enabled {
		return posture, nil
	}
	digest, err := fileSHA256(filepath.Join(h.SecurityFSDir, "ima", "ascii_runtime_measurements"))
	if err != nil {
		return gwvpn.IMAPosture{}, err
	}
	posture.LogDigest = digest
	return posture, nil
}

// fileSHA256 returns the hex SHA-256 of the file at path, or "" when there is
// no such file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, f)
	if err := errors.Join(copyErr, f.Close()); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// rootEncrypted reports whether the root filesystem sits on LUKS mappings
// only, directly or under other layers (LVM on LUKS, RAID on LUKS). The block
// device comes from the root mount's major:minor or, for a filesystem whose
// mount carries an anonymous device number, from its source device. A btrfs
// root spans every member device of its filesystem while the mount names only
// one, so every member must be LUKS-backed.
func (h *HostPosture) rootEncrypted() (bool, error) {
	devNum, fsType, source, err := h.rootMount()
	if err != nil {
		return false, err
	}
	if fsType != btrfsFSType {
		dir := filepath.Join(h.SysfsDir, "dev", "block", devNum)
		if _, err := os.Stat(dir); err == nil {
			return h.luksBacked(dir, maxStackDepth), nil
		}
	}
	device, err := sourceDevice(source)
	if err != nil || device == "" {
		return false, err
	}
	if fsType == btrfsFSType {
		return h.btrfsMembersLUKSBacked(device), nil
	}
	return h.luksBacked(filepath.Join(h.SysfsDir, "class", "block", device), maxStackDepth), nil
}

// sourceDevice returns the kernel name of the block device a mount source
// names, or "" when the source is not a device path that exists.
func sourceDevice(source string) (string, error) {
	if !filepath.IsAbs(source) {
		return "", nil
	}
	resolved, err := filepath.EvalSymlinks(source)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return filepath.Base(resolved), nil
}

// btrfsMembersLUKSBacked reports whether every member device of the btrfs
// filesystem that device belongs to is LUKS-backed. The filesystem is the one
// whose /sys/fs/btrfs/<fsid>/devices/ lists device; that directory names every
// member by its kernel name. A filesystem that cannot be found counts as
// unencrypted, and so does a member list or a member that cannot be read.
func (h *HostPosture) btrfsMembersLUKSBacked(device string) bool {
	root := filepath.Join(h.SysfsDir, "fs", "btrfs")
	filesystems, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, filesystem := range filesystems {
		devices := filepath.Join(root, filesystem.Name(), "devices")
		if _, err := os.Lstat(filepath.Join(devices, device)); err != nil {
			continue
		}
		members, err := os.ReadDir(devices)
		if err != nil {
			return false
		}
		return h.allLUKSBacked(members, maxStackDepth)
	}
	return false
}

// rootMount returns the major:minor, the filesystem type and the source of the last mount on "/"
// in the mount table: a later mount over "/" hides an earlier one.
func (h *HostPosture) rootMount() (devNum, fsType, source string, err error) {
	raw, err := os.ReadFile(h.MountInfoPath)
	if err != nil {
		return "", "", "", err
	}
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		// id parent major:minor root mount-point options [optional…] - fstype source super-options
		fields := strings.Fields(scanner.Text())
		sep := slices.Index(fields, "-")
		if len(fields) < 5 || fields[4] != "/" || sep < 0 || sep+2 >= len(fields) {
			continue
		}
		devNum, fsType, source, found = fields[2], fields[sep+1], fields[sep+2], true
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}
	if !found {
		return "", "", "", &ErrNoRootMount{MountInfo: h.MountInfoPath}
	}
	return devNum, fsType, source, nil
}

// luksBacked reports whether every path from the block device at dir (a sysfs
// block device directory) down to the physical devices passes through a LUKS
// mapping: root on LVM or RAID over one encrypted and one plain disk keeps
// data readable on the plain one. A device that is neither a LUKS mapping nor
// stacked on others is an unencrypted leaf. The walk fails closed: a part of
// the tree it cannot read, or a stack deeper than maxStackDepth, counts as
// unencrypted.
func (h *HostPosture) luksBacked(dir string, depth int) bool {
	if depth == 0 {
		return false
	}
	uuid, err := os.ReadFile(filepath.Join(dir, "dm", "uuid"))
	if err == nil && strings.HasPrefix(string(uuid), luksUUIDPrefix) {
		return true
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	slaves, err := os.ReadDir(filepath.Join(dir, "slaves"))
	if err != nil {
		return false
	}
	return h.allLUKSBacked(slaves, depth-1)
}

// allLUKSBacked reports whether there is at least one device and every named
// block device is LUKS-backed.
func (h *HostPosture) allLUKSBacked(devices []fs.DirEntry, depth int) bool {
	if len(devices) == 0 {
		return false
	}
	for _, device := range devices {
		if !h.luksBacked(filepath.Join(h.SysfsDir, "class", "block", device.Name()), depth) {
			return false
		}
	}
	return true
}

// osRelease returns the PRETTY_NAME of os-release, or "" without the file.
func (h *HostPosture) osRelease() (string, error) {
	raw, err := os.ReadFile(h.OSReleasePath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME=")
		if !ok {
			continue
		}
		if unquoted, err := strconv.Unquote(value); err == nil {
			return unquoted, nil
		}
		return strings.Trim(value, `'"`), nil
	}
	return "", nil
}

// unameRelease is the running kernel's release.
func unameRelease() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(uts.Release[:]), nil
}
