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

package entities

import (
	"fmt"
)

type System struct {
	BIOS     *BIOS          `yaml:"bios" json:"bios,omitempty"`
	Board    *Board         `yaml:"board" json:"board,omitempty"`
	CA       *CAStatus      `yaml:"ca" json:"ca,omitempty"`
	Chassis  *Chassis       `yaml:"chassis" json:"chassis,omitempty"`
	CPU      *CPUInfo       `yaml:"cpu" json:"cpu"`
	Mode     string         `yaml:"mode" json:"mode"`
	Network  *NetworkInfo   `yaml:"network" json:"network,omitempty"`
	OS       *OSInfo        `yaml:"os" json:"os,omitempty"`
	Product  *Product       `yaml:"product" json:"product"`
	Runtime  *SystemRuntime `yaml:"runtime" json:"runtime"`
	Services int            `yaml:"services" json:"services"`
	TPM      *TPMStatus     `yaml:"tpm" json:"tpm,omitempty"`
}

type CPUInfo struct {
	ModelName string   `yaml:"model" json:"model"`
	Cores     int      `yaml:"cores" json:"cores"`
	CacheSize string   `yaml:"cache" json:"cache"`
	Flags     []string `yaml:"flags" json:"flags"`
	Threads   int      `yaml:"threads" json:"threads"`
}

func (c CPUInfo) Print() {
	fmt.Printf("CPU model:             %s\n", c.ModelName)
	fmt.Printf("CPU cores:             %d\n", c.Cores)
	fmt.Printf("CPU threads:           %d\n", c.Threads)
	fmt.Printf("CPU cache size:        %s\n", c.CacheSize)
	fmt.Printf("CPU Flags:             %s\n", c.Flags)
}

type BIOS struct {
	Date    string `yaml:"date" json:"date"`
	Release string `yaml:"release" json:"release"`
	Vendor  string `yaml:"vendor" json:"vendor"`
	Version string `yaml:"version" json:"version"`
}

func (b BIOS) Print() {
	fmt.Printf("BIOS date:             %s\n", b.Date)
	fmt.Printf("BIOS release:          %s\n", b.Release)
	fmt.Printf("BIOS vendor:           %s\n", b.Vendor)
	fmt.Printf("BIOS version:          %s\n", b.Version)
}

type Board struct {
	AssetTag string `yaml:"asset-tag" json:"asset_tag"`
	Name     string `yaml:"name" json:"name"`
	Serial   string `yaml:"serial" json:"serial"`
	Vendor   string `yaml:"vendor" json:"vendor"`
	Version  string `yaml:"version" json:"version"`
}

func (b Board) Print() {
	fmt.Printf("Board asset tag:       %s\n", b.AssetTag)
	fmt.Printf("Board name:            %s\n", b.Name)
	fmt.Printf("Board serial:          %s\n", b.Serial)
	fmt.Printf("Board vendor:          %s\n", b.Vendor)
	fmt.Printf("Board version:         %s\n", b.Version)
}

type Chassis struct {
	AssetTag string `yaml:"asset-tag" json:"asset_tag"`
	Serial   string `yaml:"serial" json:"serial"`
	Type     string `yaml:"type" json:"type"`
	Vendor   string `yaml:"vendor" json:"vendor"`
	Version  string `yaml:"version" json:"version"`
}

func (c Chassis) Print() {
	fmt.Printf("Chassis asset tag:     %s\n", c.AssetTag)
	fmt.Printf("Chassis serial:        %s\n", c.Serial)
	fmt.Printf("Chassis type:          %s\n", c.Type)
	fmt.Printf("Chassis vendor:        %s\n", c.Vendor)
	fmt.Printf("Chassis version:       %s\n", c.Version)
}

type Product struct {
	Family  string `yaml:"family" json:"family"`
	Name    string `yaml:"name" json:"name"`
	Serial  string `yaml:"serial" json:"serial"`
	SKU     string `yaml:"sku" json:"sku"`
	UUID    string `yaml:"uuid" json:"uuid"`
	Version string `yaml:"version" json:"version"`
}

func (p Product) Print() {
	fmt.Printf("Product family:        %s\n", p.Family)
	fmt.Printf("Product name:          %s\n", p.Name)
	fmt.Printf("Product serial:        %s\n", p.Serial)
	fmt.Printf("Product sku:           %s\n", p.SKU)
	fmt.Printf("Product uuid:          %s\n", p.UUID)
	fmt.Printf("Product version:       %s\n", p.Version)
}

type SystemRuntime struct {
	Version     string `yaml:"version" json:"version"`
	Goroutines  int    `yaml:"goroutines" json:"goroutines"`
	Cpus        int    `yaml:"cpus" json:"cpus"`
	Cgo         int64  `yaml:"cgo" json:"cgo"`
	HeapSize    uint64 `yaml:"heap-alloc" json:"heapAlloc"`
	Alloc       uint64 `yaml:"alloc" json:"alloc"`
	Sys         uint64 `yaml:"sys" json:"sys"`
	Mallocs     uint64 `yaml:"mallocs" json:"mallocs"`
	Frees       uint64 `yaml:"frees" json:"frees"`
	NumGC       uint32 `yaml:"gc" json:"gc"`
	NumForcedGC uint32 `yaml:"num-forced-gc" json:"numForcedGC"`
}

func (sr SystemRuntime) Print() {
	fmt.Printf("Runtime version:       %s\n", sr.Version)
	fmt.Printf("Runtime goroutines:    %d\n", sr.Goroutines)
	fmt.Printf("Runtime cpus:          %d\n", sr.Cpus)
	fmt.Printf("Runtime cgo:           %d\n", sr.Cgo)
	fmt.Printf("Runtime heap size:     %d\n", sr.HeapSize)
	fmt.Printf("Runtime alloc:         %d\n", sr.Alloc)
	fmt.Printf("Runtime sys:           %d\n", sr.Sys)
	fmt.Printf("Runtime mallocs:       %d\n", sr.Mallocs)
	fmt.Printf("Runtime frees:         %d\n", sr.Frees)
	fmt.Printf("Runtime num GCs        %d\n", sr.NumGC)
	fmt.Printf("Runtime num forced GC: %d\n", sr.NumForcedGC)
}

// TPMStatus contains TPM status information
type TPMStatus struct {
	Available    bool   `yaml:"available" json:"available"`
	Manufacturer string `yaml:"manufacturer" json:"manufacturer,omitempty"`
	VendorID     string `yaml:"vendor_id" json:"vendor_id,omitempty"`
	FwVersion    string `yaml:"fw_version" json:"fw_version,omitempty"`
	FamilySpec   string `yaml:"family_spec" json:"family_spec,omitempty"`
	EKPresent    bool   `yaml:"ek_present" json:"ek_present"`
	SRKPresent   bool   `yaml:"srk_present" json:"srk_present"`
	Simulated    bool   `yaml:"simulated" json:"simulated"`
}

func (t TPMStatus) Print() {
	fmt.Printf("TPM available:         %t\n", t.Available)
	fmt.Printf("TPM manufacturer:      %s\n", t.Manufacturer)
	fmt.Printf("TPM vendor ID:         %s\n", t.VendorID)
	fmt.Printf("TPM firmware version:  %s\n", t.FwVersion)
	fmt.Printf("TPM family spec:       %s\n", t.FamilySpec)
	fmt.Printf("TPM EK present:        %t\n", t.EKPresent)
	fmt.Printf("TPM SRK present:       %t\n", t.SRKPresent)
	fmt.Printf("TPM simulated:         %t\n", t.Simulated)
}

// CAStatus contains Certificate Authority status
type CAStatus struct {
	Available   bool         `yaml:"available" json:"available"`
	RootCA      *CAKeyConfig `yaml:"root_ca" json:"root_ca,omitempty"`
	IssuingCA   *CAKeyConfig `yaml:"issuing_ca" json:"issuing_ca,omitempty"`
	CertsIssued int          `yaml:"certs_issued" json:"certs_issued"`
}

// CAKeyConfig contains the complete key configuration for a CA
type CAKeyConfig struct {
	// Identity information
	CN           string `yaml:"cn" json:"cn"`
	Organization string `yaml:"organization" json:"organization,omitempty"`
	Country      string `yaml:"country" json:"country,omitempty"`

	// Subject Alternative Names
	DNSNames []string `yaml:"dns_names" json:"dns_names,omitempty"`
	IPs      []string `yaml:"ips" json:"ips,omitempty"`

	// Validity
	ValidYears int `yaml:"valid_years" json:"valid_years,omitempty"`

	// Key configuration
	KeyAlgorithm       string `yaml:"key_algorithm" json:"key_algorithm"`
	SignatureAlgorithm string `yaml:"signature_algorithm" json:"signature_algorithm,omitempty"`
	Hash               string `yaml:"hash" json:"hash,omitempty"`

	// Algorithm-specific parameters
	KeySize  int    `yaml:"key_size" json:"key_size,omitempty"`   // RSA key size in bits
	ECCCurve string `yaml:"ecc_curve" json:"ecc_curve,omitempty"` // ECC curve name

	// Backend configuration
	StoreType      string `yaml:"store_type" json:"store_type"`
	PlatformPolicy bool   `yaml:"platform_policy" json:"platform_policy,omitempty"`

	// Parent CA (for intermediate CAs)
	ParentCA string `yaml:"parent_ca" json:"parent_ca,omitempty"`
}

func (c CAStatus) Print() {
	fmt.Printf("CA available:          %t\n", c.Available)
	if c.RootCA != nil {
		fmt.Println("\nRoot CA:")
		c.RootCA.Print("  ")
	}
	if c.IssuingCA != nil {
		fmt.Println("\nIssuing CA:")
		c.IssuingCA.Print("  ")
	}
	fmt.Printf("\nCA certs issued:       %d\n", c.CertsIssued)
}

func (k CAKeyConfig) Print(indent string) {
	fmt.Printf("%sCN:                 %s\n", indent, k.CN)
	if k.Organization != "" {
		fmt.Printf("%sOrganization:       %s\n", indent, k.Organization)
	}
	if k.Country != "" {
		fmt.Printf("%sCountry:            %s\n", indent, k.Country)
	}
	if k.ValidYears > 0 {
		fmt.Printf("%sValidity:           %d years\n", indent, k.ValidYears)
	}
	fmt.Printf("%sKey Algorithm:      %s\n", indent, k.KeyAlgorithm)
	if k.SignatureAlgorithm != "" {
		fmt.Printf("%sSignature Algo:     %s\n", indent, k.SignatureAlgorithm)
	}
	if k.KeySize > 0 {
		fmt.Printf("%sKey Size:           %d bits\n", indent, k.KeySize)
	}
	if k.ECCCurve != "" {
		fmt.Printf("%sECC Curve:          %s\n", indent, k.ECCCurve)
	}
	fmt.Printf("%sStore Type:         %s\n", indent, k.StoreType)
	if k.PlatformPolicy {
		fmt.Printf("%sPlatform Policy:    %t\n", indent, k.PlatformPolicy)
	}
	if k.ParentCA != "" {
		fmt.Printf("%sParent CA:          %s\n", indent, k.ParentCA)
	}
}

// OSInfo contains operating system information
type OSInfo struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	Kernel   string `yaml:"kernel" json:"kernel"`
	OS       string `yaml:"os" json:"os"`
	Arch     string `yaml:"arch" json:"arch"`
	Uptime   string `yaml:"uptime" json:"uptime,omitempty"`
}

func (o OSInfo) Print() {
	fmt.Printf("OS hostname:           %s\n", o.Hostname)
	fmt.Printf("OS kernel:             %s\n", o.Kernel)
	fmt.Printf("OS name:               %s\n", o.OS)
	fmt.Printf("OS arch:               %s\n", o.Arch)
	fmt.Printf("OS uptime:             %s\n", o.Uptime)
}

// NetworkInfo contains network status information
type NetworkInfo struct {
	Hostname   string   `yaml:"hostname" json:"hostname"`
	Interfaces []string `yaml:"interfaces" json:"interfaces,omitempty"`
	IPv4       string   `yaml:"ipv4" json:"ipv4,omitempty"`
	IPv6       string   `yaml:"ipv6" json:"ipv6,omitempty"`
}

func (n NetworkInfo) Print() {
	fmt.Printf("Network hostname:      %s\n", n.Hostname)
	fmt.Printf("Network interfaces:    %v\n", n.Interfaces)
	fmt.Printf("Network IPv4:          %s\n", n.IPv4)
	fmt.Printf("Network IPv6:          %s\n", n.IPv6)
}
