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

package installer

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// disklessBaseURLParam names where the boot server serves the node's media
// set; the diskless root's artifacts sit in it under their fixed names.
const disklessBaseURLParam = "platform_bin_url="

// disklessCmdlineParams are the diskless root parameters the installer signs
// into a diskless node's UKI, or none for a node that boots from its disk.
//
// The boot server marks a diskless node with platform_boot_model=diskless on
// the installer's command line. The root itself — hash, salt and sizes —
// comes only from the media set's manifest, verified against a pinned anchor
// (disklessManifestAnchors): a root hash or URL written on the live command
// line or in an iPXE script names nothing.
func (i *installer) disklessCmdlineParams(ctx context.Context, liveCmdline string) ([]string, error) {
	model, err := disklessroot.BootModelFromCmdline(liveCmdline)
	if err != nil {
		return nil, ErrUKIBuild("diskless root: reading the boot model", err)
	}
	if model != disklessroot.BootModel {
		return nil, nil
	}
	anchors, err := i.disklessManifestAnchors(ctx)
	if err != nil {
		return nil, err
	}
	params, err := disklessBootParams(liveCmdline, i.disklessManifestPath(), anchors)
	if err != nil {
		return nil, err
	}
	i.logger.Info("[UKI] Diskless root from the signed manifest", "root_hash", params.RootHash, "rootfs_url", params.RootFSURL)
	return params.Args(), nil
}

// liveCmdline is the kernel command line the installer was booted with: the
// boot server's diskless selector and diagnostics sink are read from it. An
// image target reads none, since the build host's command line describes the
// build host, and an unreadable one selects a disk node.
func (i *installer) liveCmdline() string {
	if i.skip(stepHostCmdlinePropagation) {
		return ""
	}
	path := i.cmdlineFile
	if path == "" {
		path = "/proc/cmdline"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// checkBootModel refuses a live command line whose boot model this installer
// cannot install. It installs a disk node and a diskless node; anything else,
// a diskless-nbd node included, fails here, before Install clears the TPM or
// touches a disk.
func checkBootModel(liveCmdline string) error {
	if _, err := disklessroot.BootModelFromCmdline(liveCmdline); err != nil {
		return ErrBootModel("refusing to install: unsupported boot model", err)
	}
	return nil
}

// ukiRootCmdlineParams names the root the UKI boots. A diskless node's root is
// the verified image disklessParams describe, so its command line carries no
// local root, LUKS or LVM device for dracut to wait on or unlock; a disk node
// gets those and no diskless parameters.
func (i *installer) ukiRootCmdlineParams(diskInfo *DiskInfo, disklessParams []string) []string {
	if len(disklessParams) > 0 {
		return append([]string(nil), disklessParams...)
	}

	rootDevice := diskInfo.RootPartition
	if diskInfo.LVMDevice != "" {
		rootDevice = diskInfo.LVMDevice
	} else if diskInfo.MappedDevice != "" {
		rootDevice = diskInfo.MappedDevice
	}
	params := []string{"root=" + rootDevice}

	if diskInfo.MappedDevice != "" {
		luksName := "cryptroot"
		if i.config.Disk != nil && i.config.Disk.Encryption != nil && i.config.Disk.Encryption.MappedName != "" {
			luksName = i.config.Disk.Encryption.MappedName
		}
		if diskInfo.LUKSUUID != "" {
			params = append(params,
				"rd.luks.uuid="+diskInfo.LUKSUUID,
				"rd.luks.name="+diskInfo.LUKSUUID+"="+luksName,
			)
		} else {
			i.logger.Warn("[UKI] LUKS UUID not available, using device path")
			params = append(params, "rd.luks.name="+luksName)
		}
	}

	if diskInfo.LVMDevice != "" {
		params = append(params, "rd.lvm=1")
		if diskInfo.LVMVolumeGroup != "" {
			params = append(params, "rd.lvm.vg="+diskInfo.LVMVolumeGroup)
		}
	}
	return append(params, "rootfstype=ext4")
}

// defaultPlatformDBCommonName is the subject common name of the platform's
// Secure Boot DB certificate when the config does not name one.
const defaultPlatformDBCommonName = "Trusted Platform Secure Boot DB"

// platformDBCommonName is the common name the platform's DB certificate
// carries: the configured one, else the default. The on-node generator appends
// " - <hostname>" to it.
func (i *installer) platformDBCommonName() string {
	if sb := i.config.SecureBoot; sb != nil && sb.DB.CN != "" {
		return sb.DB.CN
	}
	return defaultPlatformDBCommonName
}

// isPlatformDBCert reports whether cert is the platform's DB certificate by its
// subject common name.
func isPlatformDBCert(cert *x509.Certificate, commonName string) bool {
	cn := cert.Subject.CommonName
	return cn == commonName || strings.HasPrefix(cn, commonName+" - ")
}

// disklessManifestAnchors are the certificates a diskless node's manifest may
// verify against: the platform's DB certificate where the firmware has it
// enrolled in db, and, under resign-mode remote, the DB certificate the control
// plane's KMS signs with. Not every db entry: the firmware db also holds the
// vendor's and Microsoft's certificates, and a manifest signed by any of them
// would name the root. Never the pair the UKI signer would otherwise use — keys
// staged on the install media, a file:// pair, or one generated here — because
// those arrive with the manifest, or are made for it, and so vouch for nothing.
func (i *installer) disklessManifestAnchors(ctx context.Context) ([]*x509.Certificate, error) {
	enrolled, err := uefi.ReadDBCertificatesFromDir(i.efivarsPath())
	switch {
	case errors.Is(err, uefi.ErrEfivarsUnavailable):
		i.logger.Warn("[UKI] Diskless root: no efivarfs, so no enrolled db anchors the manifest")
	case err != nil:
		return nil, ErrUKIBuild("diskless root: reading the enrolled db", err)
	}
	var anchors []*x509.Certificate
	for _, cert := range enrolled {
		if isPlatformDBCert(cert, i.platformDBCommonName()) {
			anchors = append(anchors, cert)
		}
	}
	if kms := i.disklessKMSAnchor(ctx); kms != nil {
		anchors = append(anchors, kms)
	}
	return anchors, nil
}

// disklessKMSAnchor is the DB certificate the control plane's KMS signs with,
// or nil when resign-mode is not remote or the KMS cannot be reached.
func (i *installer) disklessKMSAnchor(ctx context.Context) *x509.Certificate {
	sb := i.config.SecureBoot
	if sb == nil || sb.ResignMode != SecureBootResignModeRemote || i.resolveRemoteSigner == nil {
		return nil
	}
	attrs, err := sb.DB.ToKeyAttributes()
	if err != nil {
		i.logger.Warn("[UKI] Diskless root: invalid DB key attributes, no KMS anchor", "error", err)
		return nil
	}
	_, cert, err := i.resolveRemoteSigner(ctx, attrs)
	if err != nil {
		i.logger.Warn("[UKI] Diskless root: KMS DB certificate unavailable", "error", err)
		return nil
	}
	return cert
}

// efivarsPath is where the firmware's variables are read.
func (i *installer) efivarsPath() string {
	if i.efivarsDir != "" {
		return i.efivarsDir
	}
	return uefi.EfivarsPath
}

// disklessBootParams verifies the manifest in dir against the anchors and
// places its artifacts under the media set's URL from the live command line.
// The URL only locates the bytes: dm-verity under the signed root hash
// decides whether they are the right ones.
func disklessBootParams(liveCmdline, dir string, anchors []*x509.Certificate) (disklessroot.BootParams, error) {
	manifest, err := readPinnedManifest(dir, anchors)
	if err != nil {
		return disklessroot.BootParams{}, err
	}
	baseURL := strings.TrimPrefix(cmdlineParam(strings.Fields(liveCmdline), disklessBaseURLParam), disklessBaseURLParam)
	params, err := disklessroot.NewBootParams(*manifest, baseURL)
	if err != nil {
		return disklessroot.BootParams{}, ErrUKIBuild("diskless root: locating the artifacts ("+disklessBaseURLParam+")", err)
	}
	return params, nil
}

// readPinnedManifest reads the manifest in dir that one of the anchors
// signed. Only a signature that fails moves on to the next anchor; a missing
// or malformed manifest fails at once.
func readPinnedManifest(dir string, anchors []*x509.Certificate) (*disklessroot.Manifest, error) {
	if len(anchors) == 0 {
		return nil, ErrUKIBuild("diskless root: no pinned anchor verifies the root manifest (the platform DB certificate is not enrolled in db and no KMS DB certificate is reachable)", nil)
	}
	var err error
	for _, anchor := range anchors {
		var manifest *disklessroot.Manifest
		manifest, err = disklessroot.ReadSigned(dir, anchor)
		if err == nil {
			return manifest, nil
		}
		var sigErr *disklessroot.SignatureError
		if !errors.As(err, &sigErr) {
			break
		}
	}
	return nil, ErrUKIBuild("diskless root: the media set's manifest", err)
}

// disklessManifestPath is where the media set's payload list lands the
// signed manifest in the install media.
func (i *installer) disklessManifestPath() string {
	if i.disklessManifestDir != "" {
		return i.disklessManifestDir
	}
	return filepath.Join(isoMediaMount, disklessroot.Dir)
}
