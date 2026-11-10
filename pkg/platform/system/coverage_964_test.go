package system

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// fakeUnavailableError is the typed error the fakes return for a missing value.
type fakeUnavailableError struct{ what string }

func (e *fakeUnavailableError) Error() string { return e.what + " unavailable" }

// fakeTPM overrides only the methods TPMInfo calls; any other method panics
// through the nil embedded interface, which flags an unexpected call.
type fakeTPM struct {
	xkmssdk.TrustedPlatformModule
	props    *xkmssdk.PropertiesFixed
	propsErr error
	info     string
	infoErr  error
	ekErr    error
	srkErr   error
}

func (f *fakeTPM) FixedProperties() (*xkmssdk.PropertiesFixed, error) {
	return f.props, f.propsErr
}

func (f *fakeTPM) Info() (string, error) { return f.info, f.infoErr }

func (f *fakeTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{}, f.ekErr
}

func (f *fakeTPM) SSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{}, f.srkErr
}

// fakeCA overrides only the methods CAInfo calls.
type fakeCA struct {
	trustedca.CACertificateAuthority
	issuing trustedca.CAIdentity
	root    *x509.Certificate
	rootErr error
}

func (f *fakeCA) IssuingIdentity() trustedca.CAIdentity { return f.issuing }

func (f *fakeCA) TrustedRoot() (*x509.Certificate, error) { return f.root, f.rootErr }

func rootIdentity() trustedca.CAIdentity {
	var id trustedca.CAIdentity
	id.Subject.CommonName = "Root CA"
	id.Subject.Organization = "Example Org"
	id.Subject.Country = "US"
	id.Valid = 10
	id.IsRoot = true
	id.KeystoreType = "pkcs8"
	key := &xkmssdk.KeyConfig{KeyAlgorithm: "RSA", Hash: "SHA-256"}
	key.RSAConfig = newOf(key.RSAConfig)
	key.RSAConfig.KeySize = 4096
	id.Keys = []*xkmssdk.KeyConfig{key}
	return id
}

func intermediateIdentity() trustedca.CAIdentity {
	var id trustedca.CAIdentity
	id.Subject.CommonName = "Issuing CA"
	id.Valid = 5
	id.ParentCA = "Root CA"
	key := &xkmssdk.KeyConfig{KeyAlgorithm: "ECDSA"}
	key.ECCConfig = newOf(key.ECCConfig)
	key.ECCConfig.Curve = "P-384"
	id.Keys = []*xkmssdk.KeyConfig{key}
	return id
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"zero", 0, "0m"},
		{"minutes only", 59 * time.Minute, "59m"},
		{"hours and minutes", 3*time.Hour + 7*time.Minute, "3h 7m"},
		{"exact day", 24 * time.Hour, "1d 0h 0m"},
		{"days hours minutes", 50*time.Hour + 5*time.Minute + 30*time.Second, "2d 2h 5m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatUptime(tt.in); got != tt.want {
				t.Fatalf("formatUptime(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSignatureAlgorithmHash(t *testing.T) {
	tests := []struct {
		in   x509.SignatureAlgorithm
		want crypto.Hash
	}{
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA256WithRSAPSS, crypto.SHA256},
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA384WithRSAPSS, crypto.SHA384},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.SHA512WithRSAPSS, crypto.SHA512},
		{x509.ECDSAWithSHA512, crypto.SHA512},
		{x509.PureEd25519, crypto.SHA512},
		{x509.UnknownSignatureAlgorithm, crypto.SHA256},
	}
	for _, tt := range tests {
		t.Run(tt.in.String(), func(t *testing.T) {
			if got := signatureAlgorithmHash(tt.in); got != tt.want {
				t.Fatalf("signatureAlgorithmHash(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestFirstOrEmpty(t *testing.T) {
	if got := firstOrEmpty(nil); got != "" {
		t.Fatalf("firstOrEmpty(nil) = %q, want empty", got)
	}
	if got := firstOrEmpty([]string{"a", "b"}); got != "a" {
		t.Fatalf("firstOrEmpty = %q, want a", got)
	}
}

func TestReadDMIFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bios_vendor")
	if err := os.WriteFile(path, []byte("  Acme BIOS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readDMIFile(path); got != "Acme BIOS" {
		t.Fatalf("readDMIFile = %q, want trimmed %q", got, "Acme BIOS")
	}
	if got := readDMIFile(filepath.Join(dir, "missing")); got != "" {
		t.Fatalf("readDMIFile(missing) = %q, want empty", got)
	}
}

func TestDMIReaders(t *testing.T) {
	const dmi = "/sys/class/dmi/id/"

	bios, err := BIOS()
	if err != nil {
		t.Fatalf("BIOS: %v", err)
	}
	if bios.Vendor != readDMIFile(dmi+"bios_vendor") || bios.Version != readDMIFile(dmi+"bios_version") {
		t.Fatalf("BIOS fields do not match DMI: %+v", bios)
	}

	board, err := Board()
	if err != nil {
		t.Fatalf("Board: %v", err)
	}
	if board.Name != readDMIFile(dmi+"board_name") || board.Vendor != readDMIFile(dmi+"board_vendor") {
		t.Fatalf("Board fields do not match DMI: %+v", board)
	}

	chassis, err := Chassis()
	if err != nil {
		t.Fatalf("Chassis: %v", err)
	}
	if chassis.Type != readDMIFile(dmi+"chassis_type") || chassis.Vendor != readDMIFile(dmi+"chassis_vendor") {
		t.Fatalf("Chassis fields do not match DMI: %+v", chassis)
	}

	product, err := Product()
	if err != nil {
		t.Fatalf("Product: %v", err)
	}
	if product.Name != readDMIFile(dmi+"product_name") || product.Family != readDMIFile(dmi+"product_family") {
		t.Fatalf("Product fields do not match DMI: %+v", product)
	}
}

func TestCPUInfo(t *testing.T) {
	cpu, err := CPUInfo()
	if err != nil {
		t.Fatalf("CPUInfo: %v", err)
	}
	// Every logical CPU has one "processor" stanza in /proc/cpuinfo.
	if cpu.Threads < 1 {
		t.Fatalf("CPUInfo threads = %d, want at least 1", cpu.Threads)
	}
}

func TestSystemInfo(t *testing.T) {
	sys, err := SystemInfo()
	if err != nil {
		t.Fatalf("SystemInfo: %v", err)
	}
	if sys.Runtime == nil || sys.Runtime.Version != runtime.Version() || sys.Runtime.Cpus != runtime.NumCPU() {
		t.Fatalf("SystemInfo runtime = %+v, want version %s and %d CPUs", sys.Runtime, runtime.Version(), runtime.NumCPU())
	}
	if sys.CPU == nil || sys.CPU.Threads < 1 {
		t.Fatalf("SystemInfo CPU = %+v, want populated", sys.CPU)
	}
	// DMI tables are only read as root.
	if root := os.Geteuid() == 0; (sys.BIOS != nil) != root {
		t.Fatalf("SystemInfo BIOS present = %v, want %v", sys.BIOS != nil, root)
	}
	if err := PrintSystemInfo(); err != nil {
		t.Fatalf("PrintSystemInfo: %v", err)
	}
}

func TestOSInfoDetails(t *testing.T) {
	info := OSInfoDetails()
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname != hostname || info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("OSInfoDetails = %+v", info)
	}
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if want := strings.Fields(string(data))[2]; info.Kernel != want {
			t.Fatalf("Kernel = %q, want %q", info.Kernel, want)
		}
	}
	if _, err := os.Stat("/proc/uptime"); err == nil && !strings.HasSuffix(info.Uptime, "m") {
		t.Fatalf("Uptime = %q, want a formatted duration", info.Uptime)
	}
}

func TestNetworkInfoDetails(t *testing.T) {
	info := NetworkInfoDetails()
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname != hostname {
		t.Fatalf("Hostname = %q, want %q", info.Hostname, hostname)
	}
	for _, name := range info.Interfaces {
		if name == "lo" {
			t.Fatal("loopback interface must be skipped")
		}
	}
	if info.IPv4 == "127.0.0.1" {
		t.Fatal("loopback address must be skipped")
	}
}

func TestTPMInfo(t *testing.T) {
	unavailable := &fakeUnavailableError{what: "key"}
	tests := []struct {
		name string
		tpm  *fakeTPM
		want func(t *testing.T, s *entities.TPMStatus)
	}{
		{
			name: "simulator with keys",
			tpm: &fakeTPM{
				props: &xkmssdk.PropertiesFixed{Manufacturer: "IBM", VendorID: "SW TPM", FwMajor: 1, FwMinor: 38, Family: "2.0"},
				info:  "TPM 2.0 Simulator",
			},
			want: func(t *testing.T, s *entities.TPMStatus) {
				if !s.Available || s.Manufacturer != "IBM" || s.VendorID != "SW TPM" || s.FwVersion != "1.38" || s.FamilySpec != "2.0" {
					t.Fatalf("properties not mapped: %+v", *s)
				}
				if !s.Simulated || !s.EKPresent || !s.SRKPresent {
					t.Fatalf("flags not set: %+v", *s)
				}
			},
		},
		{
			name: "swtpm info is simulated",
			tpm:  &fakeTPM{info: "SWTPM vendor"},
			want: func(t *testing.T, s *entities.TPMStatus) {
				if !s.Simulated {
					t.Fatal("swtpm must be reported as simulated")
				}
			},
		},
		{
			name: "hardware tpm with every query failing",
			tpm: &fakeTPM{
				propsErr: unavailable,
				info:     "Infineon",
				infoErr:  unavailable,
				ekErr:    unavailable,
				srkErr:   unavailable,
			},
			want: func(t *testing.T, s *entities.TPMStatus) {
				if !s.Available || s.Manufacturer != "" || s.FwVersion != "" {
					t.Fatalf("failed queries must leave fields empty: %+v", *s)
				}
				if s.Simulated || s.EKPresent || s.SRKPresent {
					t.Fatalf("failed queries must clear flags: %+v", *s)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, TPMInfo(tt.tpm))
		})
	}

	if s := TPMInfo(nil); s.Available || s.Manufacturer != "" {
		t.Fatalf("TPMInfo(nil) = %+v, want unavailable", *s)
	}
}

func TestCAInfo(t *testing.T) {
	if s := CAInfo(nil); s.Available || s.RootCA != nil {
		t.Fatalf("CAInfo(nil) = %+v, want unavailable", *s)
	}

	if s := CAInfo(&fakeCA{}); !s.Available || s.RootCA != nil || s.IssuingCA != nil {
		t.Fatalf("CAInfo without issuing CN = %+v, want available with no identities", *s)
	}

	root := CAInfo(&fakeCA{issuing: rootIdentity()})
	if root.RootCA == nil || root.RootCA.CN != "Root CA" || root.IssuingCA != root.RootCA {
		t.Fatalf("root-only CA must report the root as issuer: %+v", *root)
	}

	rootCert := &x509.Certificate{Subject: pkix.Name{
		CommonName:   "Chain Root",
		Organization: []string{"Chain Org"},
		Country:      []string{"DE"},
	}}
	inter := CAInfo(&fakeCA{issuing: intermediateIdentity(), root: rootCert})
	if inter.IssuingCA == nil || inter.IssuingCA.CN != "Issuing CA" || inter.IssuingCA.ParentCA != "Root CA" {
		t.Fatalf("issuing CA = %+v", inter.IssuingCA)
	}
	if inter.RootCA == nil || inter.RootCA.CN != "Chain Root" || inter.RootCA.Organization != "Chain Org" || inter.RootCA.Country != "DE" {
		t.Fatalf("root synthesized from chain = %+v", inter.RootCA)
	}

	noRoot := CAInfo(&fakeCA{issuing: intermediateIdentity(), rootErr: &fakeUnavailableError{what: "root"}})
	if noRoot.IssuingCA == nil || noRoot.RootCA != nil {
		t.Fatalf("root lookup failure must leave RootCA nil: %+v", *noRoot)
	}
}

func TestIdentityToKeyConfig(t *testing.T) {
	id := rootIdentity()
	rsa := identityToKeyConfig(&id)
	if rsa.CN != "Root CA" || rsa.Organization != "Example Org" || rsa.Country != "US" || rsa.ValidYears != 10 || rsa.StoreType != "pkcs8" {
		t.Fatalf("identity fields not mapped: %+v", rsa)
	}
	if rsa.KeyAlgorithm != "RSA" || rsa.KeySize != 4096 || rsa.SignatureAlgorithm != x509.SHA256WithRSA.String() || rsa.Hash != crypto.SHA256.String() {
		t.Fatalf("RSA key config not mapped: %+v", rsa)
	}

	inter := intermediateIdentity()
	ecc := identityToKeyConfig(&inter)
	if ecc.ECCCurve != "P-384" || ecc.SignatureAlgorithm != x509.ECDSAWithSHA384.String() || ecc.Hash != crypto.SHA384.String() {
		t.Fatalf("ECDSA key config not mapped: %+v", ecc)
	}

	// An identity without keys has no signature algorithm to derive.
	var bare trustedca.CAIdentity
	bare.Subject.CommonName = "Bare"
	if kc := identityToKeyConfig(&bare); kc.CN != "Bare" || kc.SignatureAlgorithm != "" || kc.KeyAlgorithm != "" {
		t.Fatalf("keyless identity = %+v", kc)
	}
}

func TestIdentityToKeyConfigSANs(t *testing.T) {
	id := rootIdentity()
	// The SAN type is not re-exported; allocate it through the field's type.
	id.SANS = newOf(id.SANS)
	id.SANS.DNS = []string{"ca.example.com"}
	id.SANS.IPs = []string{"10.0.0.1"}
	kc := identityToKeyConfig(&id)
	if len(kc.DNSNames) != 1 || kc.DNSNames[0] != "ca.example.com" || len(kc.IPs) != 1 || kc.IPs[0] != "10.0.0.1" {
		t.Fatalf("SANs not mapped: %+v", kc)
	}
}

func TestCAInfoFromConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     *trustedca.CAConfig
		available  bool
		issuingCN  string
		issuerRoot bool
	}{
		{name: "nil config"},
		{name: "no identities", config: &trustedca.CAConfig{}},
		{name: "root only", config: &trustedca.CAConfig{Identity: []trustedca.CAIdentity{rootIdentity()}}, available: true, issuingCN: "Root CA", issuerRoot: true},
		{name: "selected intermediate", config: &trustedca.CAConfig{Identity: []trustedca.CAIdentity{rootIdentity(), intermediateIdentity()}, SelectedCA: 1}, available: true, issuingCN: "Issuing CA"},
		{name: "selected out of range", config: &trustedca.CAConfig{Identity: []trustedca.CAIdentity{rootIdentity()}, SelectedCA: 3}, available: true, issuingCN: "Root CA", issuerRoot: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := CAInfoFromConfig(tt.config)
			if s.Available != tt.available {
				t.Fatalf("Available = %v, want %v", s.Available, tt.available)
			}
			if !tt.available {
				if s.RootCA != nil || s.IssuingCA != nil {
					t.Fatalf("unavailable CA must have no identities: %+v", *s)
				}
				return
			}
			if s.RootCA == nil || s.RootCA.CN != "Root CA" {
				t.Fatalf("RootCA = %+v, want index 0", s.RootCA)
			}
			if s.IssuingCA == nil || s.IssuingCA.CN != tt.issuingCN {
				t.Fatalf("IssuingCA = %+v, want %s", s.IssuingCA, tt.issuingCN)
			}
			if (s.IssuingCA == s.RootCA) != tt.issuerRoot {
				t.Fatalf("issuer is root = %v, want %v", s.IssuingCA == s.RootCA, tt.issuerRoot)
			}
		})
	}
}

// newOf allocates a zero value of the type p points to.
func newOf[T any](_ *T) *T { return new(T) }
