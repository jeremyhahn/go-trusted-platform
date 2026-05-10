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

package bmc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Vendor identifies the BMC manufacturer.
//
// Vendor selection drives which CertificateManager and (where Redfish
// AccountService support is patchy) which UserManager backend is most
// appropriate. Detection is performed by probing the Redfish service
// root and inspecting the Vendor field and Oem extension keys.
type Vendor string

const (
	// VendorUnknown indicates the vendor could not be determined.
	VendorUnknown Vendor = "unknown"

	// VendorSupermicro indicates a Supermicro BMC (ATEN-based on X10/X11,
	// AMI-based on X12+).
	VendorSupermicro Vendor = "supermicro"

	// VendorDell indicates a Dell iDRAC BMC.
	VendorDell Vendor = "dell"

	// VendorHPE indicates an HPE iLO BMC.
	VendorHPE Vendor = "hpe"

	// VendorLenovo indicates a Lenovo XClarity BMC.
	VendorLenovo Vendor = "lenovo"

	// VendorGeneric indicates a Redfish-compliant BMC of an unidentified
	// vendor; only standards-compliant code paths are safe.
	VendorGeneric Vendor = "generic"
)

// validVendors is a map-based lookup for valid vendor values.
var validVendors = map[Vendor]struct{}{
	VendorUnknown:    {},
	VendorSupermicro: {},
	VendorDell:       {},
	VendorHPE:        {},
	VendorLenovo:     {},
	VendorGeneric:    {},
}

// IsValid reports whether v is a recognized vendor.
func (v Vendor) IsValid() bool {
	_, ok := validVendors[v]
	return ok
}

// vendorOEMKey maps Redfish Oem extension keys to their canonical Vendor.
// Probed in addition to the standardized Vendor field for older firmware
// (X10 ATEN BMCs in particular often omit the Vendor field but always
// populate Oem.Supermicro).
var vendorOEMKey = map[string]Vendor{
	"Supermicro": VendorSupermicro,
	"Dell":       VendorDell,
	"Hpe":        VendorHPE,
	"Hp":         VendorHPE,
	"Lenovo":     VendorLenovo,
}

// vendorNameMatch maps lower-cased substrings appearing in the Vendor
// field to the canonical Vendor. Matched after case folding so variations
// like "Supermicro Computer, Inc." and "DELL" both resolve cleanly.
var vendorNameMatch = map[string]Vendor{
	"supermicro": VendorSupermicro,
	"dell":       VendorDell,
	"hpe":        VendorHPE,
	"hewlett":    VendorHPE,
	"lenovo":     VendorLenovo,
}

// vendorManufacturer maps a detected Vendor to the canonical Redfish
// System.Manufacturer string used as the manufacturer key for pkg/quirks
// registry lookups. Empty string is returned for VendorUnknown / VendorGeneric
// — those resolve to the generic Default quirk via pkg/quirks.Resolve.
var vendorManufacturer = map[Vendor]string{
	VendorSupermicro: "Supermicro",
	VendorDell:       "Dell Inc.",
	VendorHPE:        "HPE",
	VendorLenovo:     "Lenovo",
}

// ManufacturerString returns the canonical Redfish System.Manufacturer string
// associated with v, suitable for passing as the manufacturer argument to
// pkg/quirks.Resolve. Returns "" for unknown / generic vendors (which resolve
// to the generic Default quirk).
func (v Vendor) ManufacturerString() string {
	return vendorManufacturer[v]
}

// recommendedCertBackend maps a detected Vendor to the cert-management
// backend that should be tried first under CertBackendAuto. Operators
// can always pin via CertBackendRedfish or CertBackendSMCCGI.
var recommendedCertBackend = map[Vendor]CertBackend{
	VendorSupermicro: CertBackendSMCCGI, // X10 ATEN; X11+ may upgrade to Redfish
	VendorDell:       CertBackendRedfish,
	VendorHPE:        CertBackendRedfish,
	VendorLenovo:     CertBackendRedfish,
	VendorGeneric:    CertBackendRedfish,
	VendorUnknown:    CertBackendRedfish,
}

// RecommendCertBackend returns the cert backend that should be tried
// first for the given vendor under auto-mode selection.
func RecommendCertBackend(v Vendor) CertBackend {
	if backend, ok := recommendedCertBackend[v]; ok {
		return backend
	}
	return CertBackendRedfish
}

// vendorProbeRoot is the subset of the Redfish service root needed for
// vendor identification. Defined separately from redfishServiceRoot to
// keep vendor probing decoupled from the full Redfish client lifecycle
// (no session, no discovery cache, no resource path resolution).
type vendorProbeRoot struct {
	RedfishVersion string                     `json:"RedfishVersion"`
	Vendor         string                     `json:"Vendor"`
	Oem            map[string]json.RawMessage `json:"Oem"`
}

// VendorProbe identifies the manufacturer of a BMC by issuing a single
// unauthenticated GET against /redfish/v1/.
//
// The probe is intentionally lightweight: no session establishment, no
// resource discovery, no caching. Callers wanting to reuse the result
// should store it themselves. SkipTLSVerify and CACertPath from cfg are
// honored so the probe can run against BMCs presenting their initial
// self-signed certificate (the common case before TLS provisioning).
type VendorProbe struct {
	httpClient *http.Client
	logger     *slog.Logger
}

// NewVendorProbe builds a VendorProbe that uses cfg's TLS settings.
func NewVendorProbe(cfg *Config, logger *slog.Logger) (*VendorProbe, error) {
	if cfg == nil {
		return nil, ErrNilConfig{}
	}
	tlsConfig, err := buildVendorProbeTLS(cfg)
	if err != nil {
		return nil, err
	}
	return &VendorProbe{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		logger: logger,
	}, nil
}

// Detect probes the BMC at cfg.Address:cfg.Port and returns the resolved
// Vendor. Returns VendorUnknown with a nil error if the Redfish service
// root is reachable but does not identify a recognized vendor; returns
// a non-nil error if the probe itself fails.
func (p *VendorProbe) Detect(ctx context.Context, cfg *Config) (Vendor, error) {
	if cfg == nil {
		return VendorUnknown, ErrNilConfig{}
	}
	url := fmt.Sprintf("https://%s:%d/redfish/v1/", cfg.Address, cfg.Port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return VendorUnknown, ErrConnectionFailed{Address: cfg.Address, Cause: err}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return VendorUnknown, ErrConnectionFailed{Address: cfg.Address, Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return VendorUnknown, ErrConnectionFailed{
			Address: cfg.Address,
			Cause:   ErrRedfishServiceRootStatus{Status: resp.StatusCode},
		}
	}

	var root vendorProbeRoot
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		return VendorUnknown, ErrConnectionFailed{Address: cfg.Address, Cause: err}
	}

	v := classifyVendor(root)
	if p.logger != nil {
		p.logger.Info("bmc: vendor probe complete",
			slog.String("address", cfg.Address),
			slog.String("vendor", string(v)),
			slog.String("redfish_version", root.RedfishVersion))
	}
	return v, nil
}

// classifyVendor resolves a vendor from a parsed service root using the
// standardized Vendor field first and falling back to Oem extension keys.
func classifyVendor(root vendorProbeRoot) Vendor {
	if root.Vendor != "" {
		lower := strings.ToLower(root.Vendor)
		for needle, vendor := range vendorNameMatch {
			if strings.Contains(lower, needle) {
				return vendor
			}
		}
	}
	for key, vendor := range vendorOEMKey {
		if _, ok := root.Oem[key]; ok {
			return vendor
		}
	}
	if root.RedfishVersion != "" {
		// Service root parsed but no vendor signal — generic Redfish.
		return VendorGeneric
	}
	return VendorUnknown
}

// buildVendorProbeTLS mirrors the redfishClient TLS config logic but is
// scoped to probe usage so it can be exercised independently in tests.
func buildVendorProbeTLS(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.SkipTLSVerify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // BMC self-signed cert support, guarded by config flag
	}
	if cfg.CACertPath != "" {
		pool, err := loadCAPool(cfg.CACertPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}
