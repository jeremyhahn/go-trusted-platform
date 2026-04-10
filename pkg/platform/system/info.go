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

package system

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

func PrintSystemInfo() error {

	sys, err := SystemInfo()
	if err != nil {
		return err
	}

	if sys.CPU != nil {
		sys.CPU.Print()
		fmt.Println()
	}

	if sys.BIOS != nil {
		sys.BIOS.Print()
		fmt.Println()
	}

	if sys.Board != nil {
		sys.Board.Print()
		fmt.Println()
	}

	if sys.Chassis != nil {
		sys.Chassis.Print()
		fmt.Println()
	}

	if sys.Product != nil {
		sys.Product.Print()
		fmt.Println()
	}

	sys.Runtime.Print()
	fmt.Println()
	return nil
}

func CPUInfo() (entities.CPUInfo, error) {

	var cpuInfo entities.CPUInfo
	totalThreads := 0

	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return cpuInfo, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "processor":
			totalThreads++
		case "model name":
			if cpuInfo.ModelName == "" {
				cpuInfo.ModelName = value
			}
		case "cpu cores":
			if cpuInfo.Cores == 0 {
				fmt.Sscanf(value, "%d", &cpuInfo.Cores)
			}
		case "cache size":
			if cpuInfo.CacheSize == "" {
				cpuInfo.CacheSize = value
			}
		case "flags":
			if len(cpuInfo.Flags) == 0 {
				cpuInfo.Flags = strings.Fields(value) // Split flags by whitespace
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return cpuInfo, err
	}

	cpuInfo.Threads = totalThreads

	return cpuInfo, nil

}

func SystemInfo() (entities.System, error) {

	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)

	systemInfo := entities.System{
		Runtime: &entities.SystemRuntime{
			Version:     runtime.Version(),
			Cpus:        runtime.NumCPU(),
			Cgo:         runtime.NumCgoCall(),
			Goroutines:  runtime.NumGoroutine(),
			HeapSize:    memstats.HeapAlloc, // essentially what the profiler is giving you (active heap memory)
			Alloc:       memstats.Alloc,     // similar to HeapAlloc, but for all go managed memory
			Sys:         memstats.Sys,       // the total amount of memory (address space) requested from the OS
			Mallocs:     memstats.Mallocs,
			Frees:       memstats.Frees,
			NumGC:       memstats.NumGC,
			NumForcedGC: memstats.NumForcedGC,
		},
	}

	cpuInfo, err := CPUInfo()
	if err != nil {
		return systemInfo, err
	}
	systemInfo.CPU = &cpuInfo

	if os.Geteuid() == 0 {
		bios, err := BIOS()
		if err != nil {
			return entities.System{}, err
		}
		board, err := Board()
		if err != nil {
			return entities.System{}, err
		}
		chassis, err := Chassis()
		if err != nil {
			return entities.System{}, err
		}
		product, err := Product()
		if err != nil {
			return entities.System{}, err
		}
		systemInfo.BIOS = &bios
		systemInfo.Board = &board
		systemInfo.Chassis = &chassis
		systemInfo.Product = &product
	}

	return systemInfo, nil
}

// readDMIFile reads a DMI file and returns empty string if it doesn't exist.
// This allows the system info functions to work in VMs where DMI files may be missing.
func readDMIFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func BIOS() (entities.BIOS, error) {
	return entities.BIOS{
		Date:    readDMIFile("/sys/class/dmi/id/bios_date"),
		Release: readDMIFile("/sys/class/dmi/id/bios_release"),
		Vendor:  readDMIFile("/sys/class/dmi/id/bios_vendor"),
		Version: readDMIFile("/sys/class/dmi/id/bios_version"),
	}, nil
}

func Board() (entities.Board, error) {
	return entities.Board{
		AssetTag: readDMIFile("/sys/class/dmi/id/board_asset_tag"),
		Name:     readDMIFile("/sys/class/dmi/id/board_name"),
		Serial:   readDMIFile("/sys/class/dmi/id/board_serial"),
		Vendor:   readDMIFile("/sys/class/dmi/id/board_vendor"),
		Version:  readDMIFile("/sys/class/dmi/id/board_version"),
	}, nil
}

func Chassis() (entities.Chassis, error) {
	return entities.Chassis{
		AssetTag: readDMIFile("/sys/class/dmi/id/chassis_asset_tag"),
		Serial:   readDMIFile("/sys/class/dmi/id/chassis_serial"),
		Type:     readDMIFile("/sys/class/dmi/id/chassis_type"),
		Vendor:   readDMIFile("/sys/class/dmi/id/chassis_vendor"),
		Version:  readDMIFile("/sys/class/dmi/id/chassis_version"),
	}, nil
}

func Product() (entities.Product, error) {
	return entities.Product{
		Family:  readDMIFile("/sys/class/dmi/id/product_family"),
		Name:    readDMIFile("/sys/class/dmi/id/product_name"),
		Serial:  readDMIFile("/sys/class/dmi/id/product_serial"),
		SKU:     readDMIFile("/sys/class/dmi/id/product_sku"),
		UUID:    readDMIFile("/sys/class/dmi/id/product_uuid"),
		Version: readDMIFile("/sys/class/dmi/id/product_version"),
	}, nil
}

// TPMInfo gathers TPM status information
func TPMInfo(tpm xkmssdk.TrustedPlatformModule) *entities.TPMStatus {
	status := &entities.TPMStatus{
		Available: tpm != nil,
	}

	if tpm == nil {
		return status
	}

	// Get TPM fixed properties
	props, err := tpm.FixedProperties()
	if err == nil && props != nil {
		status.Manufacturer = props.Manufacturer
		status.VendorID = props.VendorID
		status.FwVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
		status.FamilySpec = props.Family
	}

	// Check if simulated TPM
	info, err := tpm.Info()
	if err == nil {
		status.Simulated = strings.Contains(strings.ToLower(info), "simulator") ||
			strings.Contains(strings.ToLower(info), "swtpm")
	}

	// Check if EK is present
	_, err = tpm.EKAttributes()
	status.EKPresent = err == nil

	// Check if SRK is present
	_, err = tpm.SSRKAttributes()
	status.SRKPresent = err == nil

	return status
}

// CAInfo gathers CA status information
func CAInfo(certAuth trustedca.CACertificateAuthority) *entities.CAStatus {
	status := &entities.CAStatus{
		Available: certAuth != nil,
	}

	if certAuth == nil {
		return status
	}

	// Get CA configuration which contains key info
	config := certAuth.CAConfig()

	// Populate root CA info
	rootIdentity := config.RootIdentity()
	if rootIdentity != nil && rootIdentity.Subject.CommonName != "" {
		status.RootCA = identityToKeyConfig(rootIdentity, &config)
	}

	// Populate issuing (intermediate) CA info if configured
	if config.HasIntermediate() {
		status.IssuingCA = identityToKeyConfig(config.IntermediateIdentity(), &config)
	} else {
		// If no intermediate, the root is also the issuing CA
		status.IssuingCA = status.RootCA
	}

	return status
}

// identityToKeyConfig converts a CA identity to a CAKeyConfig entity
func identityToKeyConfig(identity *trustedca.CAIdentity, config *trustedca.CAConfig) *entities.CAKeyConfig {
	keyConfig := &entities.CAKeyConfig{
		// Identity information
		CN:           identity.Subject.CommonName,
		Organization: identity.Subject.Organization,
		Country:      identity.Subject.Country,

		// Validity
		ValidYears: identity.Valid,

		// Key configuration
		KeyAlgorithm: identity.KeyAlgorithm.String(),

		// Algorithm-specific parameters
		KeySize:  identity.KeySize,
		ECCCurve: identity.ECCCurve,

		// Backend configuration
		StoreType: identity.KeystoreType,

		// Parent CA (for intermediate CAs)
		ParentCA: identity.ParentCA,
	}

	// Set signature algorithm - derive from key algorithm if not set in config
	if config.DefaultSignatureAlgorithm != 0 {
		keyConfig.SignatureAlgorithm = config.DefaultSignatureAlgorithm.String()
		keyConfig.Hash = signatureAlgorithmHash(config.DefaultSignatureAlgorithm).String()
	} else {
		// Derive signature algorithm from key algorithm
		sigAlgo := deriveSignatureAlgorithm(identity)
		keyConfig.SignatureAlgorithm = sigAlgo.String()
		keyConfig.Hash = signatureAlgorithmHash(sigAlgo).String()
	}

	// Populate SANs if available
	if identity.SANS != nil {
		keyConfig.DNSNames = identity.SANS.DNS
		keyConfig.IPs = identity.SANS.IPs
	}

	return keyConfig
}

// deriveSignatureAlgorithm returns an appropriate x509.SignatureAlgorithm based on the key algorithm
func deriveSignatureAlgorithm(identity *trustedca.CAIdentity) x509.SignatureAlgorithm {
	switch identity.KeyAlgorithm {
	case x509.RSA:
		if identity.KeySize >= 4096 {
			return x509.SHA512WithRSA
		} else if identity.KeySize >= 3072 {
			return x509.SHA384WithRSA
		}
		return x509.SHA256WithRSA
	case x509.ECDSA:
		switch identity.ECCCurve {
		case "P-521", "P521":
			return x509.ECDSAWithSHA512
		case "P-384", "P384":
			return x509.ECDSAWithSHA384
		default:
			return x509.ECDSAWithSHA256
		}
	case x509.Ed25519:
		return x509.PureEd25519
	default:
		return x509.SHA256WithRSA
	}
}

// signatureAlgorithmHash returns the crypto.Hash for a given signature algorithm
func signatureAlgorithmHash(sigAlgo x509.SignatureAlgorithm) crypto.Hash {
	switch sigAlgo {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return crypto.SHA512
	case x509.PureEd25519:
		return crypto.SHA512 // Ed25519 uses SHA-512 internally
	default:
		return crypto.SHA256
	}
}

// CAInfoFromConfig gathers CA status information directly from Config.
// This uses the Identity array which includes the Keys field with full key configurations.
func CAInfoFromConfig(config *trustedca.CAConfig) *entities.CAStatus {
	status := &entities.CAStatus{
		Available: config != nil && len(config.Identity) > 0,
	}

	if config == nil || len(config.Identity) == 0 {
		return status
	}

	// Root CA is always index 0
	rootIdentity := config.Identity[0]
	status.RootCA = identityToKeyConfig(&rootIdentity, config)

	// Issuing CA is at SelectedCA index (or root if not set)
	if config.SelectedCA > 0 && config.SelectedCA < len(config.Identity) {
		issuingIdentity := config.Identity[config.SelectedCA]
		status.IssuingCA = identityToKeyConfig(&issuingIdentity, config)
	} else {
		status.IssuingCA = status.RootCA
	}

	return status
}

// OSInfoDetails gathers operating system information
func OSInfoDetails() *entities.OSInfo {
	hostname, _ := os.Hostname()

	info := &entities.OSInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}

	// Read kernel version from /proc/version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			info.Kernel = parts[2] // Third field is usually the version
		}
	}

	// Read uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 1 {
			var upSeconds float64
			fmt.Sscanf(parts[0], "%f", &upSeconds)
			duration := time.Duration(upSeconds) * time.Second
			info.Uptime = formatUptime(duration)
		}
	}

	return info
}

// NetworkInfoDetails gathers network information
func NetworkInfoDetails() *entities.NetworkInfo {
	hostname, _ := os.Hostname()

	info := &entities.NetworkInfo{
		Hostname:   hostname,
		Interfaces: []string{},
	}

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		info.Interfaces = append(info.Interfaces, iface.Name)

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.IsLoopback() {
				continue
			}

			if ip.To4() != nil && info.IPv4 == "" {
				info.IPv4 = ip.String()
			} else if ip.To4() == nil && info.IPv6 == "" {
				// IPv6
				if !ip.IsLinkLocalUnicast() {
					info.IPv6 = ip.String()
				}
			}
		}
	}

	return info
}

// formatUptime formats a duration as human readable uptime
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
