package entities

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// captureStdout redirects stdout to capture Print() output.
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestCPUInfo_Print(t *testing.T) {
	cpu := CPUInfo{
		ModelName: "Intel i9",
		Cores:     8,
		CacheSize: "16MB",
		Flags:     []string{"avx2", "sse4"},
		Threads:   16,
	}

	output := captureStdout(func() { cpu.Print() })
	assert.Contains(t, output, "Intel i9")
	assert.Contains(t, output, "8")
	assert.Contains(t, output, "16")
	assert.Contains(t, output, "16MB")
}

func TestBIOS_Print(t *testing.T) {
	bios := BIOS{
		Date:    "01/01/2025",
		Release: "1.0",
		Vendor:  "ACME",
		Version: "F.20",
	}

	output := captureStdout(func() { bios.Print() })
	assert.Contains(t, output, "01/01/2025")
	assert.Contains(t, output, "ACME")
	assert.Contains(t, output, "F.20")
}

func TestBoard_Print(t *testing.T) {
	board := Board{
		AssetTag: "AT-001",
		Name:     "X670E",
		Serial:   "SN-12345",
		Vendor:   "ASUS",
		Version:  "1.0",
	}

	output := captureStdout(func() { board.Print() })
	assert.Contains(t, output, "AT-001")
	assert.Contains(t, output, "X670E")
	assert.Contains(t, output, "ASUS")
}

func TestChassis_Print(t *testing.T) {
	chassis := Chassis{
		AssetTag: "CH-001",
		Serial:   "CS-12345",
		Type:     "Desktop",
		Vendor:   "Dell",
		Version:  "1.0",
	}

	output := captureStdout(func() { chassis.Print() })
	assert.Contains(t, output, "CH-001")
	assert.Contains(t, output, "Desktop")
	assert.Contains(t, output, "Dell")
}

func TestProduct_Print(t *testing.T) {
	product := Product{
		Family:  "Server",
		Name:    "PowerEdge R750",
		Serial:  "PE-12345",
		SKU:     "SKU-001",
		UUID:    "550e8400-e29b-41d4-a716-446655440000",
		Version: "1.0",
	}

	output := captureStdout(func() { product.Print() })
	assert.Contains(t, output, "Server")
	assert.Contains(t, output, "PowerEdge R750")
	assert.Contains(t, output, "PE-12345")
	assert.Contains(t, output, "SKU-001")
	assert.Contains(t, output, "550e8400")
}

func TestSystemRuntime_Print(t *testing.T) {
	runtime := SystemRuntime{
		Version:     "go1.21.0",
		Goroutines:  42,
		Cpus:        8,
		Cgo:         5,
		HeapSize:    1024000,
		Alloc:       512000,
		Sys:         2048000,
		Mallocs:     1000,
		Frees:       500,
		NumGC:       10,
		NumForcedGC: 1,
	}

	output := captureStdout(func() { runtime.Print() })
	assert.Contains(t, output, "go1.21.0")
	assert.Contains(t, output, "42")
	assert.Contains(t, output, "8")
}

func TestTPMStatus_Print(t *testing.T) {
	tpm := TPMStatus{
		Available:    true,
		Manufacturer: "STMicroelectronics",
		VendorID:     "STM",
		FwVersion:    "4.0",
		FamilySpec:   "2.0",
		EKPresent:    true,
		SRKPresent:   true,
		Simulated:    false,
	}

	output := captureStdout(func() { tpm.Print() })
	assert.Contains(t, output, "true")
	assert.Contains(t, output, "STMicroelectronics")
	assert.Contains(t, output, "STM")
	assert.Contains(t, output, "4.0")
	assert.Contains(t, output, "2.0")
}

func TestCAStatus_Print(t *testing.T) {
	t.Run("with root and issuing CA", func(t *testing.T) {
		ca := CAStatus{
			Available: true,
			RootCA: &CAKeyConfig{
				CN:                 "Root CA",
				Organization:       "Test Org",
				Country:            "US",
				ValidYears:         10,
				KeyAlgorithm:       "RSA",
				SignatureAlgorithm: "SHA256WithRSA",
				KeySize:            4096,
				StoreType:          "software",
				PlatformPolicy:     true,
			},
			IssuingCA: &CAKeyConfig{
				CN:           "Issuing CA",
				KeyAlgorithm: "ECDSA",
				ECCCurve:     "P-384",
				StoreType:    "tpm",
				ParentCA:     "Root CA",
			},
			CertsIssued: 42,
		}

		output := captureStdout(func() { ca.Print() })
		assert.Contains(t, output, "true")
		assert.Contains(t, output, "Root CA")
		assert.Contains(t, output, "Issuing CA")
		assert.Contains(t, output, "42")
		assert.Contains(t, output, "RSA")
		assert.Contains(t, output, "ECDSA")
		assert.Contains(t, output, "P-384")
	})

	t.Run("without CAs", func(t *testing.T) {
		ca := CAStatus{
			Available:   false,
			CertsIssued: 0,
		}

		output := captureStdout(func() { ca.Print() })
		assert.Contains(t, output, "false")
	})
}

func TestCAKeyConfig_Print(t *testing.T) {
	t.Run("full config", func(t *testing.T) {
		config := CAKeyConfig{
			CN:                 "Test CA",
			Organization:       "Test Org",
			Country:            "US",
			ValidYears:         5,
			KeyAlgorithm:       "RSA",
			SignatureAlgorithm: "SHA256WithRSA",
			KeySize:            2048,
			StoreType:          "software",
			PlatformPolicy:     true,
			ParentCA:           "Root CA",
		}

		output := captureStdout(func() { config.Print("  ") })
		assert.Contains(t, output, "Test CA")
		assert.Contains(t, output, "Test Org")
		assert.Contains(t, output, "US")
		assert.Contains(t, output, "5 years")
		assert.Contains(t, output, "RSA")
		assert.Contains(t, output, "SHA256WithRSA")
		assert.Contains(t, output, "2048")
		assert.Contains(t, output, "software")
		assert.Contains(t, output, "Root CA")
	})

	t.Run("minimal config with ECC", func(t *testing.T) {
		config := CAKeyConfig{
			CN:           "ECC CA",
			KeyAlgorithm: "ECDSA",
			ECCCurve:     "P-256",
			StoreType:    "tpm",
		}

		output := captureStdout(func() { config.Print("") })
		assert.Contains(t, output, "ECC CA")
		assert.Contains(t, output, "ECDSA")
		assert.Contains(t, output, "P-256")
		// These should NOT appear since they're empty/zero
		assert.NotContains(t, output, "Organization")
		assert.NotContains(t, output, "Country")
		assert.NotContains(t, output, "Parent CA")
	})
}

func TestOSInfo_Print(t *testing.T) {
	osInfo := OSInfo{
		Hostname: "test-host",
		Kernel:   "6.5.0",
		OS:       "Linux",
		Arch:     "amd64",
		Uptime:   "5 days",
	}

	output := captureStdout(func() { osInfo.Print() })
	assert.Contains(t, output, "test-host")
	assert.Contains(t, output, "6.5.0")
	assert.Contains(t, output, "Linux")
	assert.Contains(t, output, "amd64")
	assert.Contains(t, output, "5 days")
}

func TestNetworkInfo_Print(t *testing.T) {
	network := NetworkInfo{
		Hostname:   "net-host",
		Interfaces: []string{"eth0", "wlan0"},
		IPv4:       "192.168.1.100",
		IPv6:       "::1",
	}

	output := captureStdout(func() { network.Print() })
	assert.Contains(t, output, "net-host")
	assert.Contains(t, output, "192.168.1.100")
	assert.Contains(t, output, "::1")
}

func TestUser_WebAuthnDisplayName_WithDisplayName(t *testing.T) {
	user := NewUser("test@example.com")
	user.DisplayName = "John Doe"

	assert.Equal(t, "John Doe", user.WebAuthnDisplayName())
}

func TestErrTokenGeneration_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := ErrTokenGeneration{Cause: fmt.Errorf("crypto/rand failed")}
		assert.Contains(t, err.Error(), "failed to generate secure token")
		assert.Contains(t, err.Error(), "crypto/rand failed")
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrTokenGeneration{}
		assert.Contains(t, err.Error(), "failed to generate secure token")
	})
}

func TestErrTokenGeneration_Unwrap(t *testing.T) {
	cause := fmt.Errorf("rand error")
	err := ErrTokenGeneration{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrTokenGeneration_UnwrapNil(t *testing.T) {
	err := ErrTokenGeneration{}
	assert.Nil(t, err.Unwrap())
}
