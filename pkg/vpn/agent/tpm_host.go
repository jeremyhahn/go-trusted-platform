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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"os"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	attestationservice "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
)

// DefaultPlatformConfigPaths are the platform configuration files whose
// tpm section describes the host's TPM, in the order they are tried. They
// are the files platformd and platform-initrd open the same TPM from.
var DefaultPlatformConfigPaths = []string{
	"/etc/trusted-platform/config.yaml",
	"/etc/trusted-platform/platformd.yaml",
}

// HostDeviceOptions selects how OpenHostDevice finds the host's identity.
type HostDeviceOptions struct {
	// ID is the registry device id; see TPMDeviceConfig.ID.
	ID string
	// ConfigPaths overrides DefaultPlatformConfigPaths.
	ConfigPaths []string
	// CertFile is a PEM file holding the IDevID certificate chain, leaf
	// first. Without it the leaf is read from the TPM's NV index, which
	// works only when the tpm section names the IDevID's cert-handle.
	CertFile string
}

// HostDevice is the host's TPM-backed Device. Close releases the TPM.
type HostDevice struct {
	*TPMDevice
	tpm hostTPM
}

// Close releases the TPM.
func (d *HostDevice) Close() error { return closeTPM(d.tpm) }

// hostTPM is the part of the host TPM the client device uses.
type hostTPM interface {
	attestationservice.HostQuoter
	// IDevIDCertificate reads the IDevID certificate from the TPM.
	IDevIDCertificate() (*x509.Certificate, error)
	// IDevIDSigner returns the TPM-resident IDevID key.
	IDevIDSigner() (crypto.Signer, error)
	Close() error
}

// openHostTPM opens the TPM a tpm configuration section describes. It is a
// variable so tests can open a fake instead of a TPM.
var openHostTPM = openXKMSTPM

// OpenHostDevice opens the host's TPM through the platform configuration
// and returns its device identity. A host with no TPM, no tpm section or
// an unprovisioned TPM gets ErrNoDevice.
func OpenHostDevice(opts HostDeviceOptions) (*HostDevice, error) {
	paths := opts.ConfigPaths
	if paths == nil {
		paths = DefaultPlatformConfigPaths
	}
	cfg, err := loadTPMConfig(paths)
	if err != nil {
		return nil, err
	}
	if err := identityCNs(cfg, os.Hostname); err != nil {
		return nil, err
	}
	tpm, err := openHostTPM(cfg)
	if err != nil {
		return nil, &ErrNoDevice{Reason: "the TPM could not be opened", Cause: err}
	}
	device, err := hostDevice(tpm, opts)
	if err != nil {
		return nil, errors.Join(err, closeTPM(tpm))
	}
	return &HostDevice{TPMDevice: device, tpm: tpm}, nil
}

// hostDevice builds the device over an open TPM.
func hostDevice(tpm hostTPM, opts HostDeviceOptions) (*TPMDevice, error) {
	chain, err := idevidChain(tpm, opts.CertFile)
	if err != nil {
		return nil, err
	}
	signer, err := tpm.IDevIDSigner()
	if err != nil {
		return nil, &ErrNoDevice{Reason: "the TPM has no IDevID key", Cause: err}
	}
	return NewTPMDevice(TPMDeviceConfig{ID: opts.ID, TPM: tpm, Chain: chain, Signer: signer})
}

// closeTPM closes tpm, wrapping a failure so it joins the open error.
func closeTPM(tpm hostTPM) error {
	if err := tpm.Close(); err != nil {
		return &ErrDeviceClose{Cause: err}
	}
	return nil
}

// platformTPMSection is the one section of the platform configuration the
// client reads.
type platformTPMSection struct {
	TPM *xkmssdk.TPMConfig `yaml:"tpm"`
}

// loadTPMConfig returns the tpm section of the first configuration file
// that exists. A file that exists but cannot be read or decoded is an
// error rather than a reason to try the next one.
func loadTPMConfig(paths []string) (*xkmssdk.TPMConfig, error) {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, &ErrPlatformConfig{Path: path, Cause: err}
		}
		var section platformTPMSection
		if err := config.DecodeYAML(data, &section); err != nil {
			return nil, &ErrPlatformConfig{Path: path, Cause: err}
		}
		if section.TPM == nil {
			return nil, &ErrNoDevice{Reason: path + " has no tpm section"}
		}
		return section.TPM, nil
	}
	return nil, &ErrNoDevice{Reason: "no platform configuration found"}
}

// identityCNs names the IAK and IDevID the way platformd does when the
// configuration does not (pkg/app applyTPMIdentityCNs): hostname-iak and
// hostname-idevid. Their key attributes are built from these names, and an
// empty one is refused.
func identityCNs(cfg *xkmssdk.TPMConfig, hostname func() (string, error)) error {
	nameIAK := cfg.IAK != nil && cfg.IAK.CN == ""
	nameIDevID := cfg.IDevID != nil && cfg.IDevID.CN == ""
	if !nameIAK && !nameIDevID {
		return nil
	}
	host, err := hostname()
	if err != nil {
		return &ErrNoDevice{Reason: "the hostname that names the TPM identity keys is unavailable", Cause: err}
	}
	if nameIAK {
		cfg.IAK.CN = host + "-iak"
	}
	if nameIDevID {
		cfg.IDevID.CN = host + "-idevid"
	}
	return nil
}

// idevidChain returns the IDevID chain from certFile, or the leaf alone
// from the TPM when certFile is empty.
func idevidChain(tpm hostTPM, certFile string) ([]*x509.Certificate, error) {
	if certFile == "" {
		leaf, err := tpm.IDevIDCertificate()
		if err != nil {
			return nil, &ErrIDevIDCertificate{Cause: err}
		}
		return []*x509.Certificate{leaf}, nil
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, &ErrIDevIDCertificate{Path: certFile, Cause: err}
	}
	chain, err := parseCertificateChain(data)
	if err != nil {
		return nil, &ErrIDevIDCertificate{Path: certFile, Cause: err}
	}
	return chain, nil
}

// parseCertificateChain parses every CERTIFICATE block in data, in order.
func parseCertificateChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, &ErrNoCertificate{}
	}
	return chain, nil
}

// openXKMSTPM opens the TPM through the SDK's go-xkms re-export, the way
// platform-initrd does: no key backend, blob store or certificate store,
// none of which the IDevID key or a quote needs.
func openXKMSTPM(cfg *xkmssdk.TPMConfig) (hostTPM, error) {
	if cfg.IDevID == nil {
		return nil, &ErrNoIDevIDConfig{}
	}
	// The client must not re-measure files or change the entropy source
	// platformd configured; it only quotes and signs.
	opened := *cfg
	opened.UseEntropy = false
	opened.FileIntegrity = []string{}
	tpm, err := xkmssdk.NewTPM2(&xkmssdk.TPMParams{Config: &opened, Logger: slog.Default()})
	if err != nil {
		if tpm != nil {
			return nil, errors.Join(err, tpm.Close())
		}
		return nil, err
	}
	return &xkmsTPM{TrustedPlatformModule: tpm, idevid: opened.IDevID}, nil
}

// xkmsTPM adapts the SDK's TPM to hostTPM.
type xkmsTPM struct {
	xkmssdk.TrustedPlatformModule
	idevid *xkmssdk.IDevIDConfig
}

// IDevIDSigner returns the IDevID key, built from the configuration the
// way platformd's heartbeat client builds it: the TPM's own
// IDevIDAttributes accessor rebuilds attributes that cannot sign.
func (t *xkmsTPM) IDevIDSigner() (crypto.Signer, error) {
	attrs, err := xkmssdk.IDevIDAttributesFromConfig(*t.idevid)
	if err != nil {
		return nil, err
	}
	return platform.NewTPMSigner(t.TrustedPlatformModule, attrs, nil), nil
}
