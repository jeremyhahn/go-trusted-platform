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

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	// QuicBaaS ObjectStorage client
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"

	// go-trusted-ca SDK
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmscertstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"
	acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"

	// Local platform imports
	"github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/argon2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"

	// QuicBaaS service for KMS access
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	quicbaasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	localcertstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	libtpm2 "github.com/google/go-tpm/tpm2"
)

var (
	ErrMissingEKWithoutEnabledCA        = errors.New("trusted-platform: EK certificate not found and unable to generate because the certificate authority is not enabled")
	ErrInvalidLocalAttestationSignature = errors.New("trusted-platform: local attestation signature verification failed")
	warnSimulatorWithEKCertHandle       = errors.New("trusted-platform: TPM Simulator w/ EK certificate (> 1024 bytes) configured for NV RAM storage. Using certificate store instead.")

	EnvDev     Environment = "dev"
	EnvPreProd Environment = "preprod"
	EnvProd    Environment = "prod"
	EnvTest    Environment = "test"

	TestConfig = App{
		CAConfig:         defaultCAConfig(),
		DebugFlag:        true,
		DebugSecretsFlag: true,
		ConfigDir:        "/etc/trusted-platform",
		QuicBaaSConfig: &quicbaas.Config{
			TransportStr:     "embedded",
			Transport:        quicbaas.TransportEmbedded,
			StorageBackend:   "pebble",
			DataDir:          "trusted-data/quicbaas",
			WALDir:           "trusted-data/quicbaas/wal",
			NodeID:           1,
			CacheSize:        64 * 1024 * 1024, // 64MB
			LogLevel:         "warn",
			ConsistencyLevel: quicbaas.ConsistencyLinearizable,
		},
		LogDir:           "trusted-data/log",
		Logger:           logging.DefaultLogger(),
		LogFormat:        "json",
		PlatformDir:      "trusted-data",
		Random:           rand.Reader,
		TPMConfig:        xkmssdk.DefaultTPMConfig,
		WebServiceConfig: &webservice.DefaultConfigECDSA,
		WebServices:      []*v1.Config{&webservice.DefaultConfigECDSA},
	}
)

func defaultCAConfig() *trustedca.CAConfig {
	return quicbaasca.DefaultMultiIdentityCAConfig()
}

// newKeyBackend creates a new KeyBackend using go-xkms native file storage.
// It creates a file-based storage backend at the given path.
func newKeyBackend(logger *logging.Logger, path string) (xkmssdk.TPMKeyBackend, error) {
	storageBackend, err := xkmssdk.NewFileStorageBackend(path)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create storage backend", Err: err}
	}
	return xkmssdk.NewFileBackend(logger.Slog(), storageBackend), nil
}

// initXKMSService initializes the global XKMS service with the appropriate backends
// and returns the keystore for direct use with go-trusted-ca.
//
// This function creates the keystore without any wrapper - TPM password sealing is handled
// by go-trusted-platform at a higher level before calling CA methods, using go-xkms's
// xkmssdk.PlatformPassword for just-in-time unsealing.
func (app *App) initXKMSService(caRoot string, soPIN, userPIN xkmssdk.Password) (xkmssdk.ServiceBackend, error) {
	// If XKMS was pre-initialized (in initStores before QuicBaaS start),
	// return the existing software keystore. This ensures QuicBaaS's KMS uses
	// persistent filesystem storage rather than the in-memory storage that
	// QuicBaaS's startKMS() would otherwise create.
	if xkmssdk.ServiceIsInitialized() {
		ks, err := xkmssdk.ServiceGetBackend("software")
		if err == nil {
			app.Logger.Debug("XKMS already initialized, using existing software backend")
			return ks, nil
		}
		app.Logger.Warn("XKMS initialized but software backend not found, re-initializing",
			"error", err)
		xkmssdk.ServiceReset()
	}

	var keyStorageBackend, certStorageBackend xkmssdk.StorageBackend
	var err error

	// Use memory storage for test environment, xkms file storage for production
	if app.Environment == EnvTest {
		keyStorageBackend = xkmssdk.NewStorageMemory()
		certStorageBackend = xkmssdk.NewStorageMemory()
	} else {
		// Use go-xkms native file storage for persistent key/cert backends
		keyStorageBackend, err = xkmssdk.NewFileStorageBackend(caRoot)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create key storage", Err: err}
		}
		certStorageBackend, err = xkmssdk.NewFileStorageBackend(caRoot)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create cert storage", Err: err}
		}
	}

	// Create software backend (unified backend supporting asymmetric + symmetric operations)
	softwareBackend, err := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{
		KeyStorage: keyStorageBackend,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create software backend", Err: err}
	}

	// Create software keystore
	softwareKS, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
		Backend:     softwareBackend,
		CertStorage: certStorageBackend,
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create software keystore", Err: err}
	}

	// Initialize XKMS service with backends (for code that uses xkmssdk.ServiceGetBackend())
	backends := map[string]xkmssdk.ServiceBackend{
		"software": softwareKS,
	}

	// If TPM is available, create and register a TPM2 backend
	if app.TPM != nil && app.PlatformKS != nil {
		tpm2Back, err := xkmssdk.NewTPM2BackendWithTPM(&xkmssdk.TPM2BackendExternalConfig{
			TPM:        app.TPM,
			KeyBackend: app.PlatformKS.Backend(),
			// Logger: nil - uses go-xkms's default logger
		})
		if err != nil {
			// Log warning but continue - tpm2 backend is optional
			app.Logger.Warn("Failed to create TPM2 backend for XKMS service", "error", err)
		} else {
			// Create TPM2 keystore with same cert storage as software backend
			tpm2KS, err := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
				Backend:     tpm2Back,
				CertStorage: certStorageBackend,
			})
			if err != nil {
				app.Logger.Warn("Failed to create TPM2 keystore for XKMS service", "error", err)
			} else {
				backends["tpm2"] = tpm2KS
				app.Logger.Debug("TPM2 backend registered with XKMS service")
			}
		}
	}

	if err := xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
		Backends:       backends,
		DefaultBackend: "software",
	}); err != nil {
		return nil, &WrappedError{Msg: "failed to initialize XKMS service", Err: err}
	}

	app.Logger.Debug("XKMS service initialized", "backends", len(backends))
	return softwareKS, nil
}

var DefaultConfig = App{
	CAConfig:         defaultCAConfig(),
	DebugFlag:        true,
	DebugSecretsFlag: true,
	ConfigDir:        "/etc/trusted-platform",
	QuicBaaSConfig: &quicbaas.Config{
		TransportStr:     "embedded",
		Transport:        quicbaas.TransportEmbedded,
		StorageBackend:   "pebble",
		DataDir:          "trusted-data/quicbaas",
		WALDir:           "trusted-data/quicbaas/wal",
		NodeID:           1,
		CacheSize:        64 * 1024 * 1024, // 64MB
		LogLevel:         "warn",
		ConsistencyLevel: quicbaas.ConsistencyLinearizable,
	},
	LogDir:           "trusted-data/log",
	Logger:           logging.DefaultLogger(),
	LogFormat:        "json",
	PlatformDir:      "trusted-data",
	Random:           rand.Reader,
	TPMConfig:        xkmssdk.DefaultTPMConfig,
	WebServiceConfig: &webservice.DefaultConfigECDSA,
	WebServices:      []*v1.Config{&webservice.DefaultConfigECDSA},
}

type Environment string

func (e Environment) String() string {
	return string(e)
}

func ParseEnvironment(env string) Environment {
	switch env {
	case string(EnvDev):
		return EnvDev
	case string(EnvPreProd):
		return EnvPreProd
	case string(EnvProd):
		return EnvProd
	case string(EnvTest):
		return EnvTest
	default:
		// Return user-defined environment
		return Environment(env)
	}
}

// PlatformInitConfig holds platform initialization settings including PINs.
// PIN values can be set in the YAML config to enable non-interactive startup,
// for example when using kms:// URIs resolved by the secrets engine.
type PlatformInitConfig struct {
	SOPin   string `yaml:"so-pin,omitempty" json:"so-pin,omitempty" mapstructure:"so-pin"`
	UserPin string `yaml:"user-pin,omitempty" json:"user-pin,omitempty" mapstructure:"user-pin"`
}

type App struct {
	ACMEConfig              *trustedca.ACMEConfig             `yaml:"acme" json:"acme" mapstructure:"acme" swaggerignore:"true"`
	ACMEClient              *trustedca.ACMEClient             `yaml:"-" json:"-" mapstructure:"-"`
	Argon2                  argon2.Argon2Config               `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	AttestationConfig       config.Attestation                `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	ObjectStore             object.ObjectStorer               `yaml:"-" json:"-" mapstructure:"-"`
	CA                      quicbaasca.CACertificateAuthority `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig                *trustedca.CAConfig               `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority" swaggerignore:"true"`
	ConfigDir               string                            `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	QuicBaaSConfig          *quicbaas.Config                  `yaml:"quicbaas" json:"quicbaas" mapstructure:"quicbaas"`
	DebugFlag               bool                              `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag        bool                              `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	DNSConfig               *dns.Config                       `yaml:"dns" json:"dns" mapstructure:"dns"`
	DNSService              *dns.Service                      `yaml:"-" json:"-" mapstructure:"-"`
	NTPConfig               *ntp.Config                       `yaml:"ntp,omitempty" json:"ntp,omitempty" mapstructure:"ntp"`
	NTPService              *ntp.Service                      `yaml:"-" json:"-" mapstructure:"-"`
	Domain                  string                            `yaml:"domain" json:"domain" mapstructure:"domain"`
	Environment             Environment                       `yaml:"environment" json:"environment" mapstructure:"environment"`
	Storage                 objectstorage.Client              `yaml:"-" json:"-" mapstructure:"-"`
	Hostname                string                            `yaml:"hostname" json:"hostname" mapstructure:"hostname"`
	Hostmaster              string                            `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	LogDir                  string                            `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	LogFormat               string                            `yaml:"log-format" json:"log_format" mapstructure:"log-format"`
	Logger                  *logging.Logger                   `yaml:"-" json:"-" mapstructure:"-"`
	PlatformDir             string                            `yaml:"platform-dir" json:"platform_dir" mapstructure:"platform-dir"`
	PlatformKS              xkmssdk.PlatformKeyStorer         `yaml:"-" json:"-" mapstructure:"-"`
	ManagedCertStore        xkmssdk.CertStore                 `yaml:"-" json:"-" mapstructure:"-"`
	PlatformConfig          *PlatformInitConfig               `yaml:"platform,omitempty" json:"platform,omitempty" mapstructure:"platform"`
	SecretsConfig           *SecretsConfig                    `yaml:"secrets,omitempty" json:"secrets,omitempty" mapstructure:"secrets"`
	BMCConfig               *bmc.Config                       `yaml:"bmc,omitempty" json:"bmc,omitempty" mapstructure:"bmc"`
	SDNConfig               *sdn.Config                       `yaml:"sdn,omitempty" json:"sdn,omitempty" mapstructure:"sdn"`
	ComputeConfig           *compute.OrchestratorConfig       `yaml:"compute,omitempty" json:"compute,omitempty" mapstructure:"compute"`
	SwitchConfigs           []switchmgmt.Config               `yaml:"switches,omitempty" json:"switches,omitempty" mapstructure:"switches"`
	PublicIPv4              net.IP                            `yaml:"-" json:"-" mapstructure:"-"`
	PublicIPv6              net.IP                            `yaml:"-" json:"-" mapstructure:"-"`
	PrivateIPv4             net.IP                            `yaml:"-" json:"-" mapstructure:"-"`
	PrivateIPv6             net.IP                            `yaml:"-" json:"-" mapstructure:"-"`
	Random                  io.Reader                         `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser             string                            `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	TenantID                string                            `yaml:"tenant-id" json:"tenant_id" mapstructure:"tenant-id"`
	ShutdownChan            chan bool                         `yaml:"-" json:"-" mapstructure:"-"`
	TPM                     xkmssdk.TrustedPlatformModule     `yaml:"-" json:"-" mapstructure:"-"`
	TPMCertStore            xkmssdk.TPMCertificateStorer      `yaml:"-" json:"-" mapstructure:"-"`
	TPMConfig               xkmssdk.TPMConfig                 `yaml:"tpm" json:"tpm" mapstructure:"tpm" swaggerignore:"true"`
	WebServiceConfig        *v1.Config                        `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	WebServices             []*v1.Config                      `yaml:"webservices" json:"webservices" mapstructure:"webservices"`
	WebServiceKeyAttributes map[string]*xkmssdk.KeyAttributes `yaml:"-" json:"-" mapstructure:"-"`

	// CertTargets tracks platform-wide managed certificates
	// (webservice TLS, BMC TLS, etc.) so the cert-renewal
	// scheduler handler can iterate them on every tick. Lazily
	// initialized on first use via certTargets() so zero-value
	// App instances (test constructors) need no setup.
	CertTargets *CertTargetRegistry `yaml:"-" json:"-" mapstructure:"-"`

	// Installer Configuration (System Manifest)
	// These fields define how the system is installed, provisioned, and configured.
	// They are used by the installer, initrd, and runtime components.

	// Disk configuration for system installation (partitioning, encryption, LVM)
	DiskConfig *installer.DiskConfig `yaml:"disk,omitempty" json:"disk,omitempty" mapstructure:"disk"`

	// Operating system configuration (OS type, version, packages, IMA)
	OSConfig *installer.OSConfig `yaml:"os,omitempty" json:"os,omitempty" mapstructure:"os"`

	// Network configuration for installed system (interfaces, bridges, bonds, VLANs)
	NetworkConfig *installer.NetworkConfig `yaml:"network,omitempty" json:"network,omitempty" mapstructure:"network"`

	// Unified Kernel Image configuration (kernel, initramfs, cmdline)
	UKIConfig *installer.UKIConfig `yaml:"uki,omitempty" json:"uki,omitempty" mapstructure:"uki"`

	// Secure Boot signing configuration (key, cert paths)
	SecureBootConfig *installer.SecureBootConfig `yaml:"secure-boot,omitempty" json:"secure_boot,omitempty" mapstructure:"secure-boot"`

	// Enable TPM-based LUKS key sealing
	EnableTPMSealing bool `yaml:"enable-tpm-sealing" json:"enable_tpm_sealing" mapstructure:"enable-tpm-sealing"`

	// PCR registers to seal LUKS keys against (e.g., [0, 7, 9])
	// This is the SINGLE SOURCE OF TRUTH for seal PCRs used by:
	// - Installer (initial LUKS key sealing)
	// - Initrd firstboot (writes to pcr-banks file)
	// - Initrd boot (reads from config or pcr-banks file)
	// - Runtime (TPM key sealing operations)
	SealPCRs []uint `yaml:"seal-pcrs,omitempty" json:"seal_pcrs,omitempty" mapstructure:"seal-pcrs"`

	// Number of overwrite passes for secure wipe of installer.luks
	// Options:
	//   1 = Single random pass + TRIM (NIST SP 800-88, recommended for SSDs)
	//   3 = DoD 5220.22-M (zeros, ones, random) - for compliance/HDDs
	//   7 = DoD 5220.22-M ECE (extended) - maximum security
	// Default: 1 (modern SSD-optimized)
	SecureWipePasses int `yaml:"secure-wipe-passes,omitempty" json:"secure_wipe_passes,omitempty" mapstructure:"secure-wipe-passes"`

	// Enable FIDO2 enrollment for LUKS
	EnableFIDO2Enrollment bool `yaml:"enable-fido2-enrollment" json:"enable_fido2_enrollment" mapstructure:"enable-fido2-enrollment"`

	// FIDO2 configuration for LUKS enrollment
	FIDO2Config *installer.FIDO2Config `yaml:"fido2,omitempty" json:"fido2,omitempty" mapstructure:"fido2"`

	serviceRegistry *service.Registry `yaml:"-" json:"-" mapstructure:"-"`
	daoFactory      datastore.Factory `yaml:"-" json:"-" mapstructure:"-"`

	// KMS is accessed via app.KMS() method which returns QuicBaaS's KMSService directly.
	// No configuration needed - KMS uses the QuicBaaS backend configured in QuicBaaSConfig.

	// vTPM Configuration
	// Provides pre-provisioned virtual TPM bundle management for VMs.
	VTPMConfig *vtpm.Config `yaml:"vtpm,omitempty" json:"vtpm,omitempty" mapstructure:"vtpm"`

	// Barrier configuration for platform-wide encryption at rest.
	BarrierConfig *barrier.Config `yaml:"barrier,omitempty" json:"barrier,omitempty" mapstructure:"barrier"`

	// barrier is the runtime barrier manager (not serialized).
	barrier *barrier.Manager

	// BootstrapConfig configures trust bootstrap services including the Noise_NK
	// server and DANE TLSA auto-publication.
	BootstrapConfig *bootstrap.Config `yaml:"bootstrap,omitempty" json:"bootstrap,omitempty" mapstructure:"bootstrap"`

	// TrustConfig configures the platform trust resolver: per-class
	// (default, bmc, internal) ordered strategy chains for establishing
	// TLS trust, including the client-side CA bundle fetch at first boot.
	TrustConfig *trust.Config `yaml:"trust,omitempty" json:"trust,omitempty" mapstructure:"trust"`

	// danePublisher is the runtime DANE TLSA publisher (not serialized).
	danePublisher *bootstrap.DANEPublisher

	// ovsClient is the runtime OVS client (not serialized).
	ovsClient ovs.ClientInterface

	// ipamAllocator is the runtime IPAM allocator (not serialized).
	ipamAllocator ipam.Allocator

	// trustResolver is the lazily-constructed trust Resolver built from
	// TrustConfig. It is cached here so EnrollBMC and BMCTLSProvider can
	// use the same instance without rebuilding the resolver on each call.
	// Access via app.TrustResolver().
	trustResolver trust.Resolver
}

type AppInitParams struct {
	CADir        string
	ConfigDir    string
	ConfigFile   string
	Debug        bool
	DebugSecrets bool
	Env          string
	EKCert       string
	Initialize   bool
	PlatformCA   int
	PlatformDir  string
	LogDir       string
	Pin          []byte
	RuntimeUser  string
	SOPin        []byte
}

func NewApp() *App {
	app := new(App)
	app.ShutdownChan = make(chan bool, 1)
	return app
}

// Initialize and start the platform based on the provided
// initialization parameters.
func (app *App) Init(ctx context.Context, initParams *AppInitParams) (*App, error) {
	// Override config file with CLI options FIRST (matching original behavior)
	// The config file is loaded next and will overwrite these with config values
	// This allows config file settings (like debug: true) to take effect
	// Only override directory paths if they are explicitly set (non-empty)
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.DebugSecretsFlag = initParams.DebugSecrets
		if initParams.PlatformDir != "" {
			app.PlatformDir = initParams.PlatformDir
		}
		if initParams.ConfigDir != "" {
			app.ConfigDir = initParams.ConfigDir
		}
		if initParams.LogDir != "" {
			app.LogDir = initParams.LogDir
		}
		app.Environment = ParseEnvironment(initParams.Env)
	}

	// Initialize the configuration from file
	// viper.Unmarshal will overwrite app fields with config values (including DebugFlag)
	// This is the key behavior that allows config's debug: true to prevent PIN prompts
	// Note: viper.ConfigFileUsed() returns the path set by SetConfigFile even before ReadInConfig is called,
	// so we check if TPMConfig.Device is empty to determine if config needs to be loaded
	if app.TPMConfig.Device == "" {
		env := ""
		if initParams != nil {
			env = initParams.Env
		}
		if err := app.initConfig(env); err != nil {
			return nil, err
		}
	}

	// Initialize the logger
	app.initLogger()

	// Debug: Log the environment value
	app.Logger.Debug("Environment configuration",
		"environment", string(app.Environment),
		"is_test", app.Environment == EnvTest)

	// Set the hostname
	if app.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			panic("Unable to get the local hostname")
		}
		app.Hostname = hostname
	}

	// TenantID is defaulted to "default" via viper.SetDefault in
	// pkg/daemon/commands/root.go. A blank value here indicates a
	// programming error (App constructed outside the viper-driven
	// path); we refuse to silently fill it in with a fallback.

	// Parse private and public IP addresses
	if err := app.parsePrivateAndPublicIPs(); err != nil {
		return nil, err
	}

	// Initialize the platform datastores. The QuicBaaS SecretsService comes
	// up here — everything downstream (kms:// resolution, PIN parsing, TPM
	// provisioning, CA init) depends on it.
	if err := app.initStores(); err != nil {
		return nil, err
	}

	// Provision Secure Boot PK/KEK/DB key material before secret resolution.
	// These kms:// refs carry no ?ensure=true (they are keypairs + certs, not
	// random bytes), so nothing else creates them and the fail-closed config
	// walk below would abort startup with "secret not found".
	if err := app.ProvisionSecureBootKeys(ctx); err != nil {
		return nil, &WrappedError{Msg: "secure boot key provisioning", Err: err}
	}

	// Resolve kms:// URIs in config before platform services consume them.
	// EnsureSecret provides the generate-on-first-boot / stable-on-reboot
	// semantics — no local cache file is needed. Must run after
	// initStores() (SecretsService available) and before ParsePINs() /
	// InitTPM() so the PINs used for TPM hierarchy auth are stable.
	//
	// Resolve secret URIs (kms://, credential://, idevid://, etc.) in config
	// before platform services consume them. Uses the unified qrdb ConfigProcessor
	// with fail-closed semantics: any unresolved URI aborts startup so raw URI
	// strings never reach TPM hierarchy auth, CA init, or BMC creds — which would
	// treat them as literal passwords and fail with cryptic errors (TPM_RC_SIZE, etc.).
	if app.SecretsConfig != nil && app.SecretsConfig.Enabled {
		result, err := app.ProcessSecrets(context.Background(), app.SecretsConfig)
		if err != nil {
			return nil, &WrappedError{Msg: "bootstrap secret resolution", Err: err}
		}
		if len(result.Errors) > 0 {
			for _, resolveErr := range result.Errors {
				app.Logger.Error(resolveErr, "bootstrap secret resolution error")
			}
			return nil, &MessageError{Msg: fmt.Sprintf("bootstrap secret resolution: %d field(s) failed to resolve; "+
				"refusing to start with unresolved secret URIs in config", len(result.Errors))}
		}
	}

	// Initialize the barrier manager if configured
	if app.BarrierConfig != nil {
		if err := app.initBarrier(context.Background()); err != nil {
			return nil, err
		}
	}

	// Initialize the SDN controller (OVS bridge, IPAM pools)
	// Non-fatal: SDN may not be available during early boot or on non-controller nodes
	if err := app.initSDN(context.Background()); err != nil {
		app.Logger.Warnf("SDN initialization deferred: %v", err)
	}

	// Starts the embedded DNS server
	app.StartDNS()

	// Bring the clock under platform control BEFORE TPM/CA init: TPM
	// attestation freshness, ACME issuance, DANE/DNSSEC signature windows
	// and JWT exp/nbf are all meaningless against a wrong clock. A node
	// booting years slow with no time daemon is the failure this prevents.
	if err := app.StartNTP(context.Background()); err != nil {
		return nil, err
	}

	// Parse the Security Officer and User PINs
	// When config has debug: true, prompts are skipped (matching original behavior)
	soPIN, userPIN, err := app.ParsePINs(initParams.SOPin, initParams.Pin)
	if err != nil {
		return app, err
	}

	// Defensive: catch any path where a kms:// URI slipped past the
	// bootstrap resolver. If we ever reach InitTPM with a raw URI in a
	// hierarchy-auth field, TPM2_HierarchyChangeAuth will fail with
	// TPM_RC_SIZE (the URI is typically > 32 bytes, exceeding the SHA-256
	// digest limit). Better to refuse to start with a clear message than
	// silently corrupt TPM state.
	if err := assertNoUnresolvedKMSURI("soPIN", string(soPIN.Bytes())); err != nil {
		return nil, err
	}
	if err := assertNoUnresolvedKMSURI("userPIN", string(userPIN.Bytes())); err != nil {
		return nil, err
	}

	// Mirror the resolved soPIN into TPMConfig.{SSRK,EK}.HierarchyAuth on
	// every boot — not just during ProvisionPlatform. When an already-
	// provisioned TPM reboots (handles persistent), ProvisionPlatform
	// short-circuits and never sets these fields, leaving them empty.
	// Downstream CreatePrimary / Certify calls under OWNER / ENDORSEMENT
	// then submit PasswordAuth(nil), which the TPM rejects with
	// TPM_RC_BAD_AUTH (the hierarchy auth is soPIN, established at
	// first-boot provision). Paired with the autogen cache so the
	// resolved soPIN matches the one the TPM was originally provisioned
	// with.
	if app.TPMConfig.SSRK == nil {
		app.TPMConfig.SSRK = &xkmssdk.SRKConfig{}
	}
	if app.TPMConfig.SSRK.HierarchyAuth == "" {
		app.TPMConfig.SSRK.HierarchyAuth = string(soPIN.Bytes())
	}
	if app.TPMConfig.EK == nil {
		app.TPMConfig.EK = &xkmssdk.EKConfig{}
	}
	if app.TPMConfig.EK.HierarchyAuth == "" {
		app.TPMConfig.EK.HierarchyAuth = string(soPIN.Bytes())
	}
	if err := assertNoUnresolvedKMSURI("TPMConfig.SSRK.HierarchyAuth", app.TPMConfig.SSRK.HierarchyAuth); err != nil {
		return nil, err
	}
	if err := assertNoUnresolvedKMSURI("TPMConfig.EK.HierarchyAuth", app.TPMConfig.EK.HierarchyAuth); err != nil {
		return nil, err
	}

	// Initialize the TPM / platform. InitTPM is idempotent: it calls
	// OpenTPM first; if the TPM is already provisioned (EK + IAK +
	// IDevID handles present), it returns after extending the platform
	// PCR. If the platform is not yet provisioned (e.g. first boot, new
	// node coming online), it runs ProvisionPlatform which mints IAK +
	// IDevID and — when acme.client.enrollment is configured — enrolls
	// the device via endorse-01/enroll-01 with the CP's CA.
	if err := app.InitTPM(ctx, soPIN, userPIN, initParams); err != nil {
		return nil, err
	}

	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		return app, err
	}

	// KMS is now accessed via app.KMS() which uses QuicBaaS's KMSService directly.
	// No separate initialization needed - the QuicBaaS datastore factory is already started above.

	// NOTE: CA loading is intentionally NOT done here.
	// Some commands require the platform not be fully initialized.
	// Commands that need the CA (like webservice) should call LoadCA() explicitly.
	// This matches the original go-trusted-platform behavior.
	// if app.CA == nil {
	// 	if err := app.LoadCA(soPIN, userPIN); err != nil {
	// 		return nil, err
	// 	}
	// }
	// if app.ACMEClient == nil {
	// 	if err := app.InitACMEClient(); err != nil {
	// 		return nil, err
	// 	}
	// }
	// if err := app.InitWebServices(); err != nil {
	// 	return nil, err
	// }

	return app, nil
}

// Parses the public and private IP addresses from the system
func (app *App) parsePrivateAndPublicIPs() error {
	app.PrivateIPv4 = util.PreferredIPv4()
	app.PrivateIPv6 = util.PreferredIPv6()

	publicIPv4, publicPv6, err := parsePublicIPs(app.Environment)
	if err != nil {
		// Public IP lookup failure is non-fatal - platform can work without it
		// This commonly happens in air-gapped, NAT, or firewalled environments
		app.Logger.Warn("Failed to detect public IP addresses (non-fatal)", "error", err)
		// Leave public IPs as nil - zone generation will omit records that require public IP
	} else {
		app.PublicIPv4 = publicIPv4
		app.PublicIPv6 = publicPv6
	}

	publicIPv4Str := "<none>"
	publicIPv6Str := "<none>"
	if app.PublicIPv4 != nil {
		publicIPv4Str = app.PublicIPv4.String()
	}
	if app.PublicIPv6 != nil {
		publicIPv6Str = app.PublicIPv6.String()
	}

	app.Logger.Debug("IP Addresses",
		slog.String("Private IPv4", app.PrivateIPv4.String()),
		slog.String("Private IPv6", app.PrivateIPv6.String()),
		slog.String("Public IPv4", publicIPv4Str),
		slog.String("Public IPv6", publicIPv6Str))

	return nil
}

// Returns a singleton instance of the platform service registry
// systemTenantID is the fixed ID of the system tenant created by go-qrdb's
// firstboot on first server start. It mirrors go-qrdb/pkg/tenant.SystemTenantID;
// the platform consumes it through the go-quicbaas IAM SDK rather than importing
// go-qrdb directly.
const systemTenantID = "system"

// adoptSystemTenant verifies that firstboot's system tenant exists in IAM (the
// embedded QuicBaaS server runs firstboot idempotently on Start) and adopts it
// as the platform's operating tenant, replacing the bootstrap "default"
// placeholder. The platform never seeds tenants/roles/admin itself — it consumes
// what firstboot created. On lean builds without IAM the call is a graceful
// no-op and the configured TenantID is left unchanged.
func (app *App) adoptSystemTenant(ctx context.Context) error {
	sdk := app.QuicBaaSSDKClient()
	if sdk == nil {
		return nil
	}
	iamClient := sdk.IAM()
	if iamClient == nil {
		return nil
	}
	tenantClient := iamClient.Tenant()
	if tenantClient == nil {
		return nil
	}
	t, err := tenantClient.Get(ctx, systemTenantID)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("adopt system tenant: firstboot system tenant %q not present after factory start", systemTenantID), Err: err}
	}
	app.TenantID = t.ID
	app.Logger.Info("adopted firstboot system tenant",
		slog.String("tenant_id", t.ID), slog.String("name", t.Name))
	return nil
}

func (app *App) ServiceRegistry() *service.Registry {

	if app.serviceRegistry != nil {
		return app.serviceRegistry
	}

	// Create DAO factory if not already created
	if app.daoFactory == nil {
		daoFactory, err := quicbaas.NewFactory(
			app.QuicBaaSConfig,
			app.Logger,
			nil, // CA injected later
		)
		if err != nil {
			app.Logger.FatalError(err)
		}

		// Start the QuicBaaS factory
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := daoFactory.Start(ctx); err != nil {
			app.Logger.FatalError(err)
		}
		app.Logger.Info("Started QuicBaaS factory")

		app.daoFactory = daoFactory

		// Adopt firstboot's system tenant as the platform operating
		// tenant. The embedded QuicBaaS server runs firstboot during
		// Start(), idempotently creating the system tenant + built-in
		// roles + admin in IAM. We consume that tenant via the IAM SDK
		// rather than seeding our own, replacing the bootstrap "default"
		// placeholder. No-op on lean builds without IAM.
		if err := app.adoptSystemTenant(ctx); err != nil {
			app.Logger.FatalError(err)
		}
	}

	// Create device datastore from QuicBaaS factory
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		app.Logger.FatalError(&MessageError{Msg: fmt.Sprintf("device service requires QuicBaaS factory, got %T", app.daoFactory)})
	}
	deviceDatastore := device.NewDatastore(dbFactory.Client(), app.Logger)
	deviceService, err := device.NewService(deviceDatastore)
	if err != nil {
		app.Logger.FatalError(err)
	}
	profileService, err := device.NewProfileService(deviceDatastore)
	if err != nil {
		app.Logger.FatalError(err)
	}
	templateService, err := device.NewTemplateService(deviceDatastore)
	if err != nil {
		app.Logger.FatalError(err)
	}

	var dnsService *dns.Service
	if app.DNSConfig != nil && app.DNSConfig.HasServer() {
		dnsService, err = app.newDNSService()
		if err != nil {
			app.Logger.FatalError(err)
		}
		// Assign to app field so it's accessible from serve.go for webservice DNS registration
		app.DNSService = dnsService
		// Register the DNS-backed DANE publisher with the embedded QuicBaaS
		// server so Security().Trust().PublishDANE writes TLSA records through
		// the platform DNS service. The DNS service is created lazily here, so
		// the backend can only be wired now (the embedded server was started
		// earlier with a not-yet-wired adapter).
		app.wireDANEPublisherBackend()
	}

	registry, err := service.NewRegistry(app.Logger, deviceService, profileService, templateService, dnsService, app.daoFactory)
	if err != nil {
		app.Logger.FatalError(err)
	}

	app.serviceRegistry = registry

	return registry
}

// KMS returns the QuicBaaS KMSService for key management operations.
// The service uses go-xkms types directly (xkmssdk.KeyAttributes) for all operations.
// Returns nil if the datastore backend is not QuicBaaS.
func (app *App) KMS() quicbaasservice.KMSService {
	if app.daoFactory == nil {
		app.Logger.Debug("KMS: daoFactory is nil")
		return nil
	}

	// Only QuicBaaS backend supports KMS
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		app.Logger.Debug("KMS: daoFactory is not *quicbaas.Factory")
		return nil
	}

	// Get the QuicBaaS service and return KMS
	client := dbFactory.Client()
	if client == nil {
		app.Logger.Debug("KMS: QuicBaaS client is nil")
		return nil
	}
	if !client.IsStarted() {
		app.Logger.Debug("KMS: QuicBaaS client not started")
		return nil
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		app.Logger.Debug("KMS: QuicBaaS service is nil")
		return nil
	}

	kms := dbSvc.KMS()
	if kms == nil {
		app.Logger.Debug("KMS: QuicBaaS KMS service is nil - KMS may not be enabled in QuicBaaS config")
	}
	return kms
}

// QuicBaaSService returns the full QuicBaaS service for advanced integrations.
// This provides access to all QuicBaaS capabilities including KV, Auth, IAM, and KMS.
// Returns nil if the datastore backend is not QuicBaaS.
func (app *App) QuicBaaSService() quicbaasservice.QuicBaaS {
	if app.daoFactory == nil {
		return nil
	}

	// Only QuicBaaS backend supports this
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		return nil
	}

	// Get the QuicBaaS client
	client := dbFactory.Client()
	if client == nil || !client.IsStarted() {
		return nil
	}

	return client.Service()
}

// IAMProvider is an interface for obtaining the PolicyEngine from QuicBaaS.
// This is satisfied by QuicBaaS when built with the iam tag.
type IAMProvider interface {
	GetPolicyEngine(ctx context.Context) (*quicbaassdk.IAMDomainPolicyEngine, error)
}

// DAOFactory returns the datastore factory.
// This provides access to the underlying data access layer.
func (app *App) DAOFactory() datastore.Factory {
	return app.daoFactory
}

// QuicBaaSSDKClient returns the go-quicbaas SDK client for direct SDK access.
// This provides access to all 28 QuicBaaS services via the unified SDK interface.
// Returns nil if the DAO factory is not initialized or is not a QuicBaaS factory.
func (app *App) QuicBaaSSDKClient() quicbaassdk.Client {
	if app.daoFactory == nil {
		return nil
	}
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		return nil
	}
	return dbFactory.SDK()
}

// SetQuicBaaSCA injects the platform CA into the running embedded QuicBaaS
// server so that SDK CertificateService operations (e.g. those invoked by
// provisionDaemonIdentity) are issued against the platform CA rather than
// QuicBaaS's own bootstrap CA.
//
// Must be called after App.LoadCA() or App.InitCA() succeeds and before any
// call to App.QuicBaaSSDKClient().Security().Certificate().IssueCertificate().
//
// Returns nil when the factory is not a QuicBaaS factory (no-op), when the
// factory operates in remote transport mode (the remote server manages its
// own CA), or when ca is nil. Returns a typed error only when the embedded
// server is running but the CA adapter is not ready (TLS disabled).
func (app *App) SetQuicBaaSCA(ca xkmssdk.TrustedCA) error {
	if ca == nil {
		return nil
	}
	if app.daoFactory == nil {
		return nil
	}
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		return nil
	}
	return dbFactory.SetCA(ca)
}

// Close gracefully shuts down the application and releases all resources.
// This should be called when the application is terminating.
func (app *App) Close(ctx context.Context) error {
	var errs []error

	// Stop the DAO factory if it supports lifecycle management
	if app.daoFactory != nil {
		if lifecycleFactory, ok := app.daoFactory.(datastore.LifecycleFactory); ok {
			if lifecycleFactory.IsStarted() {
				app.Logger.Info("Stopping lifecycle factory (QuicBaaS)")
				if err := lifecycleFactory.Stop(ctx); err != nil {
					errs = append(errs, &WrappedError{Msg: "failed to stop DAO factory", Err: err})
				}
			}
		}
	}

	// KMS cleanup is handled by QuicBaaS lifecycle - no separate close needed

	// Signal shutdown to any listeners
	if app.ShutdownChan != nil {
		select {
		case app.ShutdownChan <- true:
		default:
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Creates a new DNS service
func (app *App) newDNSService() (*dns.Service, error) {

	app.DNSConfig.Logger = app.Logger

	// Only set IP values if not already configured via YAML
	// This allows manual override for environments where auto-detection fails
	if app.DNSConfig.PrivateIPv4 == "" {
		app.DNSConfig.PrivateIPv4 = app.PrivateIPv4.String()
	}
	if app.DNSConfig.PrivateIPv6 == "" {
		app.DNSConfig.PrivateIPv6 = app.PrivateIPv6.String()
	}
	if app.DNSConfig.PublicIPv4 == "" {
		app.DNSConfig.PublicIPv4 = app.PublicIPv4.String()
	}
	if app.DNSConfig.PublicIPv6 == "" {
		app.DNSConfig.PublicIPv6 = app.PublicIPv6.String()
	}

	// Get QuicBaaS factory for storage
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("DNS requires QuicBaaS factory, got %T", app.daoFactory)}
	}

	// Create DNSSEC key store using QuicBaaS KMS if DNSSEC is enabled
	var dnssecKeyStore dns.DNSSECKeyStore
	if app.DNSConfig.DNSSEC != nil && app.DNSConfig.DNSSEC.Enabled {
		// Get the QuicBaaS SDK client for KMS operations
		sdkClient := dbFactory.Client().SDK()
		if sdkClient == nil {
			return nil, &MessageError{Msg: "QuicBaaS SDK client not available for DNSSEC key store"}
		}
		var err error
		dnssecKeyStore, err = dns.NewQuicBaaSKMSKeyStore(sdkClient)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create QuicBaaS KMS key store for DNSSEC", Err: err}
		}
		app.Logger.Info("DNSSEC enabled with QuicBaaS KMS key store")
	}

	// Resolve network zone names for zone-subdomain support.
	var networkZones []string
	if app.DNSConfig.ZoneSubdomains && app.SDNConfig != nil {
		resolved := app.SDNConfig.ResolvedZones()
		networkZones = make([]string, 0, len(resolved))
		for _, z := range resolved {
			networkZones = append(networkZones, string(z.Name))
		}
	}

	params := &dns.Params{
		AppName:        Name,
		AppVersion:     Version,
		Config:         app.DNSConfig,
		TenantID:       app.TenantID, // Pass platform tenant for zone authorization
		PrivateIPv4:    app.PrivateIPv4,
		PrivateIPv6:    app.PrivateIPv6,
		PublicIPv4:     app.PublicIPv4,
		PublicIPv6:     app.PublicIPv6,
		Datastore:      dns.NewDatastore(dbFactory.Client(), app.Logger),
		DNSSECKeyStore: dnssecKeyStore, // DNSSEC key management via QuicBaaS KMS
		NetworkZones:   networkZones,
	}

	return dns.NewService(params)
}

// StartDNS starts the embedded CoreDNS server. CoreDNS is only launched
// when the configuration includes a PublicServer or InternalServer.
// A resolver-only configuration is passive and does not start a server.
func (app *App) StartDNS() {
	if app.DNSConfig == nil {
		return
	}
	if !app.DNSConfig.HasServer() {
		app.Logger.Debug("DNS config present but no server configured, skipping CoreDNS startup")
		return
	}
	app.Logger.Debug("Starting DNS service")
	// Only set IP values if not already configured via YAML
	if app.DNSConfig.PrivateIPv4 == "" {
		app.DNSConfig.PrivateIPv4 = app.PrivateIPv4.String()
	}
	if app.DNSConfig.PrivateIPv6 == "" {
		app.DNSConfig.PrivateIPv6 = app.PrivateIPv6.String()
	}
	if app.DNSConfig.PublicIPv4 == "" {
		app.DNSConfig.PublicIPv4 = app.PublicIPv4.String()
	}
	if app.DNSConfig.PublicIPv6 == "" {
		app.DNSConfig.PublicIPv6 = app.PublicIPv6.String()
	}
	// Inject the shared QuicBaaS factory to avoid creating a duplicate
	// (Pebble holds an exclusive lock on the database)
	dbFactory, _ := app.daoFactory.(*quicbaas.Factory)
	if dbFactory != nil {
		dns.DatastoreFactory = dbFactory
		app.Logger.Debug("QuicBaaS factory injected for DNS zone storage")
	}

	// CRITICAL: publish the DNSSEC keystore into the plugin-level
	// global BEFORE dns.Run loads any zones. The CoreDNS plugin's
	// signZoneIfEnabled reads from the dns.KeyStore package var,
	// not from the Service struct built by newDNSService() which
	// runs LATER in the startup sequence. Without this, the first
	// zone load after Run starts fails with "DNSSEC enabled but
	// no key store and no XKMS adapter are configured" and the
	// DNS server never starts. Observed on lab-node-2 2026-04-08.
	//
	// We replicate the keystore construction from newDNSService
	// here — extracting a helper is overkill for two call sites
	// that use slightly different error propagation (one FatalErrors,
	// this one logs and continues).
	if app.DNSConfig.DNSSEC != nil && app.DNSConfig.DNSSEC.Enabled && dns.KeyStore == nil {
		if dbFactory == nil {
			app.Logger.Error(nil, "DNSSEC enabled but QuicBaaS factory unavailable; CoreDNS will fail to load zones")
		} else if sdkClient := dbFactory.Client().SDK(); sdkClient == nil {
			app.Logger.Error(nil, "DNSSEC enabled but QuicBaaS SDK client unavailable; CoreDNS will fail to load zones")
		} else if ks, err := dns.NewQuicBaaSKMSKeyStore(sdkClient); err != nil {
			app.Logger.Errorf("failed to create QuicBaaS DNSSEC key store: %v", err)
		} else if setErr := dns.SetDNSSECKeyStore(ks); setErr != nil {
			app.Logger.Errorf("failed to publish DNSSEC key store to plugin global: %v", setErr)
		} else {
			app.Logger.Info("DNSSEC key store published to plugin global (pre-CoreDNS)")
		}
	}

	// Ensure zones carry the global tenant identifier. DNSSEC signing
	// requires a non-empty TenantID on every zone; config-loaded zones
	// do not set this, so we stamp app.TenantID (defaulted to "default"
	// via viper.SetDefault in pkg/daemon/commands/root.go) onto any
	// zone missing one.
	if app.DNSConfig.PublicServer != nil && app.DNSConfig.PublicServer.Zone.TenantID == "" {
		app.DNSConfig.PublicServer.Zone.TenantID = app.TenantID
	}
	if app.DNSConfig.InternalServer != nil && app.DNSConfig.InternalServer.Zone.TenantID == "" {
		app.DNSConfig.InternalServer.Zone.TenantID = app.TenantID
	}

	// Inject resolved network zone names so the CoreDNS plugin can
	// pre-create per-zone subdomains when zone_subdomains is true.
	// The SDN config must be validated (Validate() called) before StartDNS
	// so that ResolvedZones() is populated.
	if app.DNSConfig.ZoneSubdomains && app.SDNConfig != nil {
		resolved := app.SDNConfig.ResolvedZones()
		names := make([]string, 0, len(resolved))
		for _, z := range resolved {
			names = append(names, string(z.Name))
		}
		app.DNSConfig.NetworkZones = names
		app.Logger.Debug("injecting network zone names for DNS zone-subdomains",
			"count", len(names))
	}

	dns.Run(Name, Version, app.Logger, app.DNSConfig)
}

// Returns the platform publicly routable Fully Qualified Domain Name
func (app *App) FQDN() string {
	return fmt.Sprintf("%s.%s", app.Hostname, app.Domain)
}

// GetInstallerConfig extracts an installer.Config from the App fields.
// This allows code to use the unified App config while still working with
// installer.Config for backwards compatibility.
func (app *App) GetInstallerConfig() *installer.Config {
	return &installer.Config{
		Disk:                  app.DiskConfig,
		OS:                    app.OSConfig,
		Network:               app.NetworkConfig,
		UKI:                   app.UKIConfig,
		SecureBoot:            app.SecureBootConfig,
		EnableTPMSealing:      app.EnableTPMSealing,
		PCRs:                  app.SealPCRs,
		EnableFIDO2Enrollment: app.EnableFIDO2Enrollment,
		FIDO2:                 app.FIDO2Config,
		Debug:                 app.DebugFlag,
		Environment:           string(app.Environment),
	}
}

// SetInstallerConfig populates App fields from an installer.Config.
// This is useful when loading a legacy installer config file.
func (app *App) SetInstallerConfig(cfg *installer.Config) {
	if cfg == nil {
		return
	}
	app.DiskConfig = cfg.Disk
	app.OSConfig = cfg.OS
	app.NetworkConfig = cfg.Network
	app.UKIConfig = cfg.UKI
	app.SecureBootConfig = cfg.SecureBoot
	app.EnableTPMSealing = cfg.EnableTPMSealing
	app.SealPCRs = cfg.PCRs
	app.EnableFIDO2Enrollment = cfg.EnableFIDO2Enrollment
	app.FIDO2Config = cfg.FIDO2
	if cfg.Debug {
		app.DebugFlag = cfg.Debug
	}
	if cfg.Environment != "" {
		app.Environment = ParseEnvironment(cfg.Environment)
	}
}

// WebService returns a webservice config by name, or nil if not found
func (app *App) WebService(name string) *v1.Config {
	for _, ws := range app.WebServices {
		if ws.Name == name {
			return ws
		}
	}
	return nil
}

// PrimaryWebService returns the primary webservice config.
// It first checks WebServiceConfig (singular, from yaml "webservice:"),
// then falls back to WebServices[0] (plural, from yaml "webservices:"),
// or returns nil if none configured.
func (app *App) PrimaryWebService() *v1.Config {
	if app.WebServiceConfig != nil {
		return app.WebServiceConfig
	}
	if len(app.WebServices) > 0 {
		return app.WebServices[0]
	}
	return nil
}

// Initializes the Viper configuration library and unmarshals it
// into this App struct.
func (app *App) initConfig(env string) error {
	// Check if a specific config file was already set via --config flag
	// If so, use that directly instead of searching for config.yaml
	configFile := viper.ConfigFileUsed()
	if configFile != "" {
		// Config file was explicitly specified - read it directly
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	} else {
		// No explicit config file - search for config.yaml in standard paths
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(fmt.Sprintf("etc/config/%s", Name))
		viper.AddConfigPath(fmt.Sprintf("%s/etc", app.PlatformDir))
		viper.AddConfigPath(fmt.Sprintf("$HOME/.%s/", Name))
		viper.AddConfigPath(app.ConfigDir)
		viper.AddConfigPath(".")

		if err := viper.ReadInConfig(); err != nil {
			_, ok := err.(viper.ConfigFileNotFoundError)
			if ok {
				// Try to load a config based on the environment flag
				envConfig := fmt.Sprintf("config.%s", env)
				viper.SetConfigName(envConfig)
				if err := viper.ReadInConfig(); err != nil {
					return err
				}
			} else {
				return err
			}
		}
	}

	// Unmarshal with TextUnmarshaler support for custom types
	// (e.g., quicbaas.ConsistencyLevel, Environment)
	if err := viper.Unmarshal(app, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.TextUnmarshallerHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	)); err != nil {
		return err
	}

	// Manually parse the environment from viper since the custom type
	// doesn't get decoded properly by mapstructure
	if envStr := viper.GetString("environment"); envStr != "" {
		app.Environment = ParseEnvironment(envStr)
	}

	// Populate WebServices from WebServiceConfig if WebServices is empty
	// This supports both "webservice:" (singular) and "webservices:" (plural) config formats
	if len(app.WebServices) == 0 && app.WebServiceConfig != nil {
		app.WebServices = []*v1.Config{app.WebServiceConfig}
	}

	return nil
}

// Creates a new file and STDOUT logger. If the global DebugFlag is set,
// the logger is initialized in debug mode, executing all logger.Debug*
// statements.
func (app *App) initLogger() {
	if err := os.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		panic(err)
	}
	// Name is an ldflag-populated package variable. When a build skips
	// the -X linker flag (e.g. a bare `go build ./cmd/platformd` used
	// for quick debug iteration), Name is empty and the log filename
	// becomes a hidden ".log" file with no prefix. Fall back to a
	// stable known name so the log is always discoverable by the
	// OpenRC init script and by operators grepping /var/log.
	logName := Name
	if logName == "" {
		logName = "platformd"
	}
	logfile := fmt.Sprintf("%s/%s.log", app.LogDir, logName)
	file, err := os.Create(logfile)
	if err != nil {
		panic(err)
	}
	format := logging.ParseFormat(app.LogFormat)
	if app.DebugFlag {
		app.Logger = logging.NewLoggerWithFormat(slog.LevelDebug, format, file)
	} else {
		app.Logger = logging.NewLoggerWithFormat(slog.LevelError, format, file)
	}
	app.Logger.Info("platform configuration",
		slog.String("file", viper.ConfigFileUsed()),
		slog.String("config-dir", app.ConfigDir),
		slog.String("log-dir", app.LogDir))
}

// Initialize object and certificate stores
func (app *App) initStores() error {
	// Pre-initialize XKMS with filesystem storage before QuicBaaS starts.
	// QuicBaaS's embedded server startKMS() initializes go-xkms with
	// in-memory storage. Since xkmssdk.ServiceInitialize() uses sync.Once, whoever
	// calls it first wins. By initializing here with filesystem storage,
	// QuicBaaS's second Initialize() call becomes a no-op, and all KMS
	// operations use persistent filesystem storage that survives reboots.
	if app.CAConfig != nil && len(app.CAConfig.Identity) > 0 {
		selectedCA := app.CAConfig.SelectedCA
		if selectedCA == 0 && len(app.CAConfig.Identity) > 1 {
			selectedCA = 1
		}
		issuingIdentity := app.CAConfig.Identity[selectedCA]
		caRoot := fmt.Sprintf("%s/ca/%s", app.PlatformDir, issuingIdentity.Subject.CommonName)

		if app.Environment != EnvTest {
			keyStorageBackend, storageErr := xkmssdk.NewFileStorageBackend(caRoot)
			if storageErr != nil {
				return &WrappedError{Msg: "failed to create key storage for xkms pre-init", Err: storageErr}
			}
			certStorageBackend, storageErr := xkmssdk.NewFileStorageBackend(caRoot)
			if storageErr != nil {
				return &WrappedError{Msg: "failed to create cert storage for xkms pre-init", Err: storageErr}
			}

			softwareBackend, backendErr := xkmssdk.NewSoftwareBackend(&xkmssdk.SoftwareBackendConfig{
				KeyStorage: keyStorageBackend,
			})
			if backendErr != nil {
				return &WrappedError{Msg: "failed to create software backend for xkms pre-init", Err: backendErr}
			}

			softwareKS, ksErr := xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
				Backend:     softwareBackend,
				CertStorage: certStorageBackend,
			})
			if ksErr != nil {
				return &WrappedError{Msg: "failed to create xkms keystore for pre-init", Err: ksErr}
			}

			if initErr := xkmssdk.ServiceInitialize(&xkmssdk.ServiceConfig{
				Backends:       map[string]xkmssdk.ServiceBackend{"software": softwareKS},
				DefaultBackend: "software",
			}); initErr != nil {
				return &WrappedError{Msg: "failed to pre-initialize xkms", Err: initErr}
			}

			app.Logger.Info("Pre-initialized xkms with filesystem storage",
				slog.String("caRoot", caRoot))
		}
	}

	// Initialize QuicBaaS factory early so DNS can share it
	// (DNS starts in a goroutine and needs the factory before ProvisionPlatform runs)
	if app.daoFactory == nil && app.QuicBaaSConfig != nil {
		// Parse transport configuration from YAML string value
		// This converts the transport string (e.g., "embedded", "grpc", "unix") to the Transport enum
		if err := app.QuicBaaSConfig.ParseTransportFromConfig(); err != nil {
			return &WrappedError{Msg: "failed to parse QuicBaaS transport config", Err: err}
		}

		app.Logger.Info("Initializing QuicBaaS",
			slog.String("transport", app.QuicBaaSConfig.Transport.String()),
			slog.String("address", app.QuicBaaSConfig.Address),
			slog.String("unix_socket", app.QuicBaaSConfig.UnixSocket),
			slog.String("data_dir", app.QuicBaaSConfig.DataDir))

		daoFactory, err := quicbaas.NewFactory(
			app.QuicBaaSConfig,
			app.Logger,
			nil, // CA injected later
		)
		if err != nil {
			return &WrappedError{Msg: "failed to create QuicBaaS factory", Err: err}
		}

		// Start the QuicBaaS factory
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := daoFactory.Start(ctx); err != nil {
			return &WrappedError{Msg: "failed to start QuicBaaS factory", Err: err}
		}
		app.Logger.Info("Started QuicBaaS factory",
			slog.String("transport", app.QuicBaaSConfig.Transport.String()))

		app.daoFactory = daoFactory

		// Get ObjectStorage client from the started QuicBaaS factory
		if app.Storage == nil {
			dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
			if !ok {
				return &MessageError{Msg: fmt.Sprintf("expected *quicbaas.Factory, got %T", app.daoFactory)}
			}
			sdkClient := dbFactory.SDKClient()
			if sdkClient == nil {
				return &MessageError{Msg: "QuicBaaS SDK client not available for ObjectStorage"}
			}
			app.Storage = sdkClient.ObjectStorage()
			if app.Storage == nil {
				return &MessageError{Msg: "QuicBaaS ObjectStorage client not available"}
			}
		}
	}

	// Create object store and certificate store using QuicBaaS ObjectStorage
	objectStore, err := object.NewObjectStore(app.Logger, app.Storage, app.PlatformDir, nil)
	if err != nil {
		return err
	}
	app.ObjectStore = objectStore
	cs, err := app.NewCertificateStore(objectStore)
	if err != nil {
		return err
	}
	app.ManagedCertStore = cs

	return nil
}

// Parses the Security Officer and User PINs and returns a key store
// password object for each. If the provided PINs are set to the default
// password, a new AES-256 32 byte key is generated as a password.
func (app *App) ParsePINs(soPIN, userPIN []byte) (xkmssdk.Password, xkmssdk.Password, error) {

	// Check config for PIN values (kms:// URIs are resolved to bytes by
	// resolveKMSSecrets in Init before this point).
	if soPIN == nil && app.PlatformConfig != nil && app.PlatformConfig.SOPin != "" {
		soPIN = []byte(app.PlatformConfig.SOPin)
	}
	if userPIN == nil && app.PlatformConfig != nil && app.PlatformConfig.UserPin != "" {
		userPIN = []byte(app.PlatformConfig.UserPin)
	}

	// When config has debug: true, skip prompts (config is loaded via viper.Unmarshal
	// which overwrites app.DebugFlag with the config file value)
	if !app.DebugFlag {
		if soPIN == nil {
			soPIN = prompt.SOPin()
		}
		if userPIN == nil {
			userPIN = prompt.Pin()
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Equal(soPIN, []byte(xkmssdk.DEFAULT_PASSWORD)) {
		soPIN = aesgcm.NewAESGCM(rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debug(
				"generated new Security Officer PIN", slog.String("sopin", string(soPIN)))
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Equal(userPIN, []byte(xkmssdk.DEFAULT_PASSWORD)) {
		userPIN = aesgcm.NewAESGCM(rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debug(
				"generated new User PIN", slog.String("pin", string(userPIN)))
		}
	}
	sopin := xkmssdk.NewPassword(soPIN)
	userpin := xkmssdk.NewPassword(userPIN)
	return sopin, userpin, nil
}

// Initializes the Trusted Platform Module and provisions the platform. If
// a Security Officer or User PIN is set to the default, new random 32
// byte cryptographic PIN will be generated. The random input source for
// entropy is the Golang runtime rand.Reader. Possibly in the future this
// will support a HSM TRNG.
func (app *App) InitTPM(ctx context.Context, soPIN, userPIN xkmssdk.Password, initParams *AppInitParams) error {
	err := app.OpenTPM(initParams.Initialize)
	needsProvisioning := false
	if err != nil {
		if err == xkmssdk.ErrTPMNotInitialized {
			needsProvisioning = true
		} else {
			return err
		}
	} else if app.TPMConfig.IAK != nil && app.TPMConfig.IDevID != nil && app.TPM != nil {
		// EK is resident but the platform may still be un-provisioned —
		// or PARTIALLY provisioned if a prior boot crashed mid-flow.
		// Check IAK and Platform SRK both; missing EITHER means the
		// platform needs full provisioning. This matches the reference
		// project's behavior where ProvisionPlatform owns the full
		// CreateIDevID → enroll-01 flow.
		if _, iakErr := app.TPM.IAKAttributes(); iakErr != nil {
			app.Logger.Info("IAK handle not found, platform needs provisioning",
				slog.String("error", iakErr.Error()))
			needsProvisioning = true
		} else if srkAttrs, srkErr := app.TPM.PlatformSRKAttributes(); srkErr != nil {
			app.Logger.Info("Platform SRK handle not found (partial provisioning detected), platform needs re-provisioning",
				slog.String("error", srkErr.Error()))
			needsProvisioning = true
			// Partial-state recovery: force factory reset to drop the
			// stale IAK/owner-auth state left by the prior crashed boot
			// so the fresh Provision call can set hierarchy auth cleanly.
			initParams.Initialize = true
		} else if srkAttrs != nil && srkAttrs.TPMAttributes != nil {
			// Policy drift detection: the Platform SRK's AuthPolicy is
			// locked in at CreatePrimary time. If the current
			// PlatformPolicyDigest (derived from current PCR state) does
			// not match the SRK's stored AuthPolicy, any subsequent
			// TPM2_Seal against it will fail with TPM_RC_POLICY_FAIL.
			// Force re-provisioning so the SRK gets recreated under the
			// current policy.
			if currentDigest, pdErr := app.TPM.PlatformPolicyDigest(); pdErr == nil {
				storedPolicy := srkAttrs.TPMAttributes.Public.AuthPolicy.Buffer
				if len(storedPolicy) > 0 && len(currentDigest.Buffer) > 0 &&
					!bytes.Equal(storedPolicy, currentDigest.Buffer) {
					app.Logger.Warn("Platform SRK policy drift detected — re-provisioning TPM to rebuild SRK under current PCR policy",
						slog.String("srk_auth_policy", fmt.Sprintf("%x", storedPolicy)),
						slog.String("current_digest", fmt.Sprintf("%x", currentDigest.Buffer)))
					needsProvisioning = true
					initParams.Initialize = true
				}
			}
		}
	}
	if needsProvisioning {
		// Whenever we determine a provisioning run is needed, factory
		// reset stale platform handles (preserving EKs) first. When
		// the TPM is in DA lockout or the Lockout hierarchy auth is
		// unknown, neither TPM2_Clear nor EvictControl can recover —
		// the only path is UEFI PPI ForceClear which firmware services
		// during POST with physical presence asserted (bypasses DA
		// lockout). Documented in docs/installer/factory-reset.md.
		//
		// Previously gated on initParams.Initialize (--init flag); we
		// now always run it when provisioning is required because the
		// live-ISO installer can't modprobe TPM modules in every
		// firmware environment, leaving a reinstalled system with a
		// TPM that still carries the prior install's hierarchy auth.
		// Hitting that state with Provision-only crashes platformd
		// with TPM_RC_LOCKOUT; the recovery path is the same whether
		// --init was set or not.
		if app.TPM != nil {
			app.Logger.Info("TPM provisioning required, attempting destructive factory reset (Clear via LOCKOUT + EK-preserving evict)...")
			// Pass nil (empty auth) for FactoryResetWithClear's lockout
			// authorization. The TPM2_Clear pre-pass uses LOCKOUT
			// hierarchy with empty auth, which is correct on:
			//
			//   - Fresh hardware where the LOCKOUT auth was never set
			//   - Hardware that was just cleared via UEFI PPI ForceClear
			//     (PPI clears all hierarchy auths back to empty)
			//   - Hardware where firstboot's prior FactoryReset
			//     succeeded (which also leaves LOCKOUT empty)
			//
			// Passing soPIN.Bytes() here was a long-standing bug: soPIN
			// is platformd's OWN derived auth (autogen-keyed), which it
			// uses for hierarchy auths it has set ITSELF in a prior
			// fully-provisioned run. The TPM has no record of this
			// value when LOCKOUT auth is empty, so every Clear attempt
			// returned TPM_RC_BAD_AUTH, escalated to UEFI PPI
			// ForceClear, called HardReset(), and the system entered an
			// infinite reboot loop on X10/SLB9665 hardware. The
			// firstboot strategy in pkg/firstboot/strategy.go gets
			// this right and was the model for this fix.
			resetErr := app.TPM.FactoryResetWithClear(nil)
			if resetErr != nil {
				// Treat LOCKOUT *or* BAD_AUTH on lockout/owner evict as
				// "can't recover via in-TPM ops — escalate to PPI". Both
				// errors indicate TPM state we can't authorize locally.
				errStr := resetErr.Error()
				lockedOutOrStuck := strings.Contains(errStr, "TPM_RC_LOCKOUT") ||
					strings.Contains(errStr, "TPM_RC_BAD_AUTH")
				if lockedOutOrStuck {
					// Bounded escalation: only schedule UEFI PPI
					// ForceClear + warm-reset ONCE. We mark the attempt
					// with a sentinel under /var/lib/tpm2/. If the
					// sentinel already exists, we've already booted
					// once via PPI clear and the auth is *still* not
					// empty — meaning either the PPI clear didn't
					// actually fire (firmware refused / no physical
					// presence) or the TPM was re-locked by some other
					// path between the clear and now. In either case,
					// another reboot won't help; we proceed to
					// ProvisionPlatform on the not-quite-clean TPM and
					// let it surface a real error rather than spinning.
					sentinel := "/var/lib/tpm2/ppi-clear-attempted"
					if _, sentErr := os.Stat(sentinel); sentErr == nil {
						app.Logger.Warn("UEFI PPI ForceClear was already attempted on a previous boot — TPM state still rejects empty-auth Clear; proceeding to ProvisionPlatform without further reboot",
							slog.String("error", errStr),
							slog.String("sentinel", sentinel))
					} else {
						app.Logger.Warn("TPM auth/lockout recovery path — scheduling UEFI PPI ForceClear (takes effect after reboot)",
							slog.String("error", errStr))
						if fcErr := app.TPM.ForceClear(); fcErr != nil {
							app.Logger.Warnf("ForceClear via PPI failed: %v", fcErr)
						} else {
							_ = os.MkdirAll("/var/lib/tpm2", 0o755)
							_ = os.WriteFile(sentinel, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
							app.Logger.Warn("TPM PPI ForceClear scheduled — issuing warm reset via SysRq-b so firmware services the clear")
							// Use the SysRq-based HardReset helper rather
							// than `reboot -f`. On Supermicro X10 the
							// busybox reboot path is translated into ACPI
							// S5 shutdown, which leaves the system off and
							// the PPI request unserviced until manual
							// power-on. SysRq-b forces the CPU reset vector
							// directly, skipping init/ACPI.
							go installer.HardReset()
							return xkmssdk.ErrTPMNotInitialized
						}
					}
				} else {
					app.Logger.Warnf("Factory reset failed (may be clean TPM): %v", resetErr)
				}
			} else {
				app.Logger.Info("Factory reset complete - stale platform handles cleared, EKs preserved")
				// Successful reset clears any stale PPI-clear sentinel
				// so a future legitimate stuck-auth scenario can
				// re-arm the recovery path.
				_ = os.Remove("/var/lib/tpm2/ppi-clear-attempted")
			}
		}
		if _, err := app.ProvisionPlatform(ctx, soPIN, userPIN, initParams); err != nil {
			return err
		}
	}

	// CRITICAL: Extend PCR 23 with golden measurements on EVERY boot.
	// PCR values reset to 0 on power cycle. The PlatformSRK policy
	// references PCR 23, so it MUST be extended before any seal/unseal.
	// This runs regardless of whether we just provisioned or opened existing state.
	if app.TPM != nil {

		// === PCR DEBUG: Log PCR values before CreatePlatformPolicy ===
		debugPCRs := []uint{7, 9, 23}
		if banks, pcrErr := app.TPM.ReadPCRs(debugPCRs); pcrErr != nil {
			app.Logger.Warn("InitTPM: failed to read debug PCRs before CreatePlatformPolicy",
				slog.String("error", pcrErr.Error()))
		} else {
			for _, bank := range banks {
				for _, pcr := range bank.PCRs {
					app.Logger.Info("InitTPM: PCR value BEFORE CreatePlatformPolicy",
						slog.String("algorithm", bank.Algorithm),
						slog.Int("pcr", int(pcr.ID)),
						slog.String("value", fmt.Sprintf("%x", pcr.Value)))
				}
			}
		}
		// Log configured golden PCRs and platform PCR settings
		app.Logger.Info("InitTPM: platform PCR configuration",
			slog.String("golden_pcrs", fmt.Sprintf("%v", app.TPMConfig.GoldenPCRs)),
			slog.Uint64("platform_pcr", uint64(app.TPMConfig.PlatformPCR)),
			slog.String("platform_pcr_bank", app.TPMConfig.PlatformPCRBank))

		// Log SRK auth policy from the persistent handle
		if app.TPMConfig.PlatformSRK != nil {
			srkHandle := app.TPMConfig.PlatformSRK.SRKHandle
			_, pub, readErr := app.TPM.ReadHandle(libtpm2.TPMHandle(srkHandle))
			if readErr != nil {
				app.Logger.Warn("InitTPM: failed to read SRK public area",
					slog.String("handle", fmt.Sprintf("0x%08X", srkHandle)),
					slog.String("error", readErr.Error()))
			} else {
				app.Logger.Info("InitTPM: SRK auth policy from TPM",
					slog.String("handle", fmt.Sprintf("0x%08X", srkHandle)),
					slog.String("auth_policy", fmt.Sprintf("%x", pub.AuthPolicy.Buffer)),
					slog.Int("auth_policy_len", len(pub.AuthPolicy.Buffer)))
			}
		}
		// === END PCR DEBUG ===

		extended, pcrErr := app.TPM.IsPlatformPCRExtended()
		if pcrErr != nil {
			app.Logger.Warnf("Failed to check platform PCR state: %v", pcrErr)
		} else if !extended {
			app.Logger.Info("Platform PCR not extended, restoring golden measurements...")
			if pcrErr := app.TPM.CreatePlatformPolicy(); pcrErr != nil {
				return &WrappedError{Msg: "failed to restore platform policy", Err: pcrErr}
			}
			app.Logger.Info("Platform PCR 23 extended with golden measurements")

			// === PCR DEBUG: Log PCR values AFTER CreatePlatformPolicy ===
			if banks, dbgErr := app.TPM.ReadPCRs(debugPCRs); dbgErr != nil {
				app.Logger.Warn("InitTPM: failed to read debug PCRs after CreatePlatformPolicy",
					slog.String("error", dbgErr.Error()))
			} else {
				for _, bank := range banks {
					for _, pcr := range bank.PCRs {
						app.Logger.Info("InitTPM: PCR value AFTER CreatePlatformPolicy",
							slog.String("algorithm", bank.Algorithm),
							slog.Int("pcr", int(pcr.ID)),
							slog.String("value", fmt.Sprintf("%x", pcr.Value)))
					}
				}
			}
			// Log the policy digest that was just computed
			policyDigest, pdErr := app.TPM.PlatformPolicyDigest()
			if pdErr != nil {
				app.Logger.Warn("InitTPM: failed to get platform policy digest after extension",
					slog.String("error", pdErr.Error()))
			} else {
				app.Logger.Info("InitTPM: platform policy digest AFTER CreatePlatformPolicy",
					slog.String("digest", fmt.Sprintf("%x", policyDigest.Buffer)))
			}
			pcrDigestHash, pdErr := app.TPM.PlatformPolicyDigestHash()
			if pdErr != nil {
				app.Logger.Warn("InitTPM: failed to get PCR digest hash after extension",
					slog.String("error", pdErr.Error()))
			} else {
				app.Logger.Info("InitTPM: PCR digest hash AFTER CreatePlatformPolicy",
					slog.Uint64("pcr", uint64(app.TPMConfig.PlatformPCR)),
					slog.String("hash", fmt.Sprintf("%x", pcrDigestHash)))
			}
			// === END PCR DEBUG ===

		} else {
			app.Logger.Debug("Platform PCR already extended")
		}
	}

	return nil
}

// Opens a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. A TPM software simulator is used if enabled
// in the TPM section of the platform configuration file.
func (app *App) OpenTPM(initialize bool) error {
	path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
	backend, err := newKeyBackend(app.Logger, path)
	if err != nil {
		return err
	}
	if app.TPM == nil {
		// Resolve the TPM target (hardware device | swtpm socket | simulator |
		// auto-detect) through the single platform-wide resolver so every
		// attestation, sealing, and secure-boot path selects the TPM the same
		// way. Explicit configuration always wins: a config that demands
		// hardware fails closed when the device is absent instead of silently
		// downgrading to a software TPM, and vice versa.
		resolved, err := vtpm.ResolveTPMTarget(&app.TPMConfig, app.Logger)
		if err != nil {
			return err
		}
		if resolved.Target != vtpm.TPMTargetSimulator {
			// Rewrite any "auto" sentinel to the concrete detected path so
			// go-xkms opens the resolved device and downstream consumers see
			// a concrete path.
			app.TPMConfig.Device = resolved.Device
		}
		app.Logger.Info("TPM target resolved",
			"target", resolved.Target.String(),
			"device", resolved.Device)

		var tpmCertStore xkmssdk.TPMCertificateStorer
		tpmPartition := "objects/tpm2"
		tpmObjectStore, err := object.NewObjectStore(app.Logger, app.Storage, app.PlatformDir, &tpmPartition)
		if err != nil {
			return err
		}
		// Wrap the object store for go-xkms compatibility
		tpmObjectStoreAdapter := object.NewXKMSObjectAdapter(tpmObjectStore)
		// Always create the certificate store - it's used as a fallback when NVRAM fails
		// (e.g., swtpm with certs > 1024 bytes) even if CertHandle > 0
		// Use NewCertificateStoreWithStorage to get direct storage access for custom key operations
		cs, storage, err := localcertstore.NewCertificateStoreWithStorage(app.Logger, tpmObjectStore)
		if err != nil {
			return err
		}
		// Wrap for TPM xkmssdk.TPMCertificateStorer interface with storage access
		tpmCertStore = localcertstore.NewTPM2CertStoreAdapterWithStorage(app.Logger, cs, storage)
		// Store reference for fallback access when NVRAM provisioning fails
		app.TPMCertStore = tpmCertStore
		// Ensure IAK and IDevID CNs are set to hostname if not explicitly configured
		// This provides meaningful attestation directory and certificate names
		if app.TPMConfig.IAK != nil && app.TPMConfig.IAK.CN == "" {
			app.TPMConfig.IAK.CN = fmt.Sprintf("%s-iak", app.Hostname)
			app.Logger.Info("Set IAK CN from hostname", "cn", app.TPMConfig.IAK.CN)
		}
		if app.TPMConfig.IDevID != nil && app.TPMConfig.IDevID.CN == "" {
			app.TPMConfig.IDevID.CN = fmt.Sprintf("%s-idevid", app.Hostname)
			app.Logger.Info("Set IDevID CN from hostname", "cn", app.TPMConfig.IDevID.CN)
		}

		// Create go-xkms logger (using slog directly)
		xkmsLogger := app.Logger.Slog()
		params := &xkmssdk.TPMParams{
			Backend:      backend,
			BlobStore:    tpmObjectStoreAdapter,
			CertStore:    tpmCertStore,
			Config:       &app.TPMConfig,
			DebugSecrets: app.DebugSecretsFlag,
			FQDN:         app.FQDN(),
			Logger:       xkmsLogger,
		}
		var tpm xkmssdk.TrustedPlatformModule
		tpm, err = xkmssdk.NewTPM2(params)
		// set required globals before checking / returning errors
		app.TPM = tpm
		if app.TPMConfig.UseEntropy {
			app.Random = app.TPM
		} else {
			app.Random = rand.Reader
		}
		// now check and return errors if encountered
		if err != nil {
			return err
		}
	}

	// Check if EK is provisioned. The TPM object is created above so
	// callers (InitTPM → ProvisionPlatform) can use app.TPM even when
	// this returns ErrTPMNotInitialized.
	if app.TPMConfig.EK == nil {
		return xkmssdk.ErrTPMNotInitialized
	}

	// Post-provisioning checks — only run when EK exists (TPM is fully provisioned).
	// Re-extend the platform PCR with golden measurements if not already extended.
	// This is required on every boot to restore PCR values for TPM-sealed secrets.
	// PCR values are volatile and reset to 0 on every power cycle.
	// NOTE: This must run regardless of EK state — PCR extension doesn't
	// depend on the EK and is needed for PlatformSRK policy verification.
	extended, err := app.TPM.IsPlatformPCRExtended()
	if err != nil {
		app.Logger.Warnf("Failed to check platform PCR state: %v", err)
	} else if !extended {
		app.Logger.Info("Platform PCR not extended, restoring golden measurements...")
		if err := app.TPM.CreatePlatformPolicy(); err != nil {
			return &WrappedError{Msg: "failed to restore platform policy", Err: err}
		}
		app.Logger.Info("Platform PCR extended with golden measurements")
	} else {
		app.Logger.Debug("Platform PCR already extended")
	}

	// Check if EK is already provisioned in the TPM.
	// If initialize=true but EK exists (e.g., swtpm state carried over),
	// log a warning and continue without re-initialization.
	if ekAttrs, err := app.TPM.EKAttributes(); err == nil && ekAttrs != nil {
		if initialize {
			app.Logger.Warn("Initialize flag set but EK already exists in TPM. " +
				"Skipping re-initialization (swtpm state may have been carried over).")
			app.Logger.Debugf("Existing EK: %s", ekAttrs.CN)
		}
	}

	return nil
}

// Returns the Platform key store. This is a TPM 2.0 key store used as
// a generic key and password store by the platform. The key store will
// be created and initialized if it doesn't already exist.
//
// The Platform KeyStore has its own dedicated SRK at handle 0x81000002
// (configured via TPMConfig.PlatformSRK.SRKHandle). This is different from
// the SSRK at 0x81000001.
//
// If the Platform KeyStore SRK doesn't exist, Initialize() is called
// to create it with the provided PINs.
func (app *App) InitPlatformKeyStore(soPIN, userPIN xkmssdk.Password) error {
	app.Logger.Info("Initializing platform (TPM 2.0) key store")
	if app.PlatformKS == nil {
		path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
		backend, err := newKeyBackend(app.Logger, path)
		if err != nil {
			return err
		}

		// Set default CN if not configured
		if app.TPMConfig.PlatformSRK.CN == "" {
			app.TPMConfig.PlatformSRK.CN = "platform"
		}

		// Create the Platform KeyStore - this checks if SRK exists at configured handle
		ks, err := platform.NewPlatformKeyStore(
			app.TPM,
			backend,
			app.TPMConfig.PlatformSRK,
		)
		if err != nil {
			// Check if it's an initialization error - if so, initialize the Platform KeyStore SRK
			if errors.Is(err, platform.ErrXKMSNotInitialized) {
				app.Logger.Info("Platform KeyStore SRK not found, initializing...",
					"handle", fmt.Sprintf("0x%08x", app.TPMConfig.PlatformSRK.SRKHandle),
					"platform_policy", app.TPMConfig.PlatformSRK.PlatformPolicy)

				// Decide between Initialize(soPIN, userPIN) and
				// InitializeWithDefaults() based on whether the TPM owner
				// hierarchy actually has auth set. The platform keystore
				// SRK is created in the OWNER hierarchy; passing a non-nil
				// hierarchy-auth when the TPM has empty owner auth fails
				// with TPM_RC_BAD_AUTH.
				//
				// Signal: TPMConfig.SSRK.HierarchyAuth. The SSRK and
				// PlatformSRK share the same (OWNER) hierarchy, so if the
				// operator configured an empty owner auth for SSRK, it
				// must also be empty for PlatformSRK. Previously the code
				// unconditionally used Initialize() with a randomly
				// autogenerated soPIN as hierarchy auth, which failed on
				// every fresh TPM because firstboot intentionally leaves
				// owner auth empty per
				// docs/installer/factory-reset.md. Diagnosed 2026-04-08
				// on lab-node-2: hierarchy_auth_hex showed the 8-digit
				// autogen numeric soPIN instead of the expected empty.
				useDefaults := app.TPMConfig.SSRK == nil || app.TPMConfig.SSRK.HierarchyAuth == ""
				if useDefaults {
					app.Logger.Info("Platform KeyStore: TPM owner hierarchy is unauthenticated (SSRK.HierarchyAuth empty), initializing with defaults")
					if err := ks.InitializeWithDefaults(); err != nil {
						return &WrappedError{Msg: "failed to initialize Platform KeyStore SRK (defaults)", Err: err}
					}
				} else {
					app.Logger.Info("Platform KeyStore: TPM owner hierarchy is authenticated, initializing with soPIN/userPIN")
					if err := ks.Initialize(string(soPIN.Bytes()), string(userPIN.Bytes())); err != nil {
						return &WrappedError{Msg: "failed to initialize Platform KeyStore SRK", Err: err}
					}
				}
				app.Logger.Info("Platform KeyStore SRK created successfully")
			} else {
				return &WrappedError{Msg: "failed to create Platform KeyStore", Err: err}
			}
		}

		app.PlatformKS = ks
	}
	return nil
}

// Initializes a new ACME client using the account email provided in the
// platform configuration.
func (app *App) InitACMEClient(ctx context.Context, initialize bool) error {
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil {
		return nil
	}

	// Get account signer from CA
	if app.CA == nil {
		return errors.New("CA not configured")
	}
	signer, err := app.CA.Signer(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get account signer", Err: err}
	}

	// Create ACME storage factory using QuicBaaS ObjectStorage
	storageFactory, err := acmequicbaas.NewFactory(app.Storage)
	if err != nil {
		return &WrappedError{Msg: "failed to create storage factory", Err: err}
	}

	// Create account and certificate storage DAOs
	accountDAO, err := storageFactory.AccountDAO()
	if err != nil {
		return &WrappedError{Msg: "failed to create account DAO", Err: err}
	}
	certDAO, err := storageFactory.CertificateDAO()
	if err != nil {
		return &WrappedError{Msg: "failed to create certificate DAO", Err: err}
	}

	// Get account email
	var accountEmail string
	if app.ACMEConfig.Client.Account != nil {
		accountEmail = app.ACMEConfig.Client.Account.Email
	}

	// Build ACME client config with trusted roots
	trustedRoots := app.ACMEConfig.Client.TrustedRoots
	if trustedRoots == nil {
		trustedRoots = []string{}
	}

	// Load CA bundle from well-known file paths as fallback
	// This provides reliable trust bootstrapping when:
	// 1. The OS trust store isn't properly updated
	// 2. request-server-bundle fails due to network issues
	// 3. The CA bundle was embedded in the ISO during installation
	caBundlePaths := []string{
		"/usr/local/share/ca-certificates/trusted-platform-ca.crt", // Alpine installer target
		filepath.Join(app.ConfigDir, "ca-bundle.pem"),              // Config directory
		filepath.Join(app.PlatformDir, "ca-bundle.pem"),            // Platform directory
		"/media/cdrom/configs/ca-bundle.pem",                       // ISO mount point
	}
	for _, bundlePath := range caBundlePaths {
		if bundleData, err := os.ReadFile(bundlePath); err == nil {
			app.Logger.Info("Loaded CA bundle from file", "path", bundlePath)
			trustedRoots = append(trustedRoots, string(bundleData))
			break // Use the first one found
		}
	}

	clientConfig := &trustedca.ACMEClientConfig{
		DirectoryURL:        app.ACMEConfig.Client.DirectoryURL,
		SystemCertPool:      app.ACMEConfig.Client.SystemCertPool,
		RequestServerBundle: app.ACMEConfig.Client.RequestServerBundle,
		TrustedRoots:        trustedRoots,
	}

	app.Logger.Info("ACME client config",
		"directoryURL", clientConfig.DirectoryURL,
		"systemCertPool", clientConfig.SystemCertPool,
		"requestServerBundle", clientConfig.RequestServerBundle,
		"trustedRootsCount", len(clientConfig.TrustedRoots))

	// Get DNS resolver for ACME operations.
	// Priority: 1) ACME client dns-server, 2) dns.resolver, 3) DNS service, 4) System resolver
	dnsResolver := app.DNSResolverForService(app.ACMEConfig.Client.DNSServer)
	if dnsResolver != nil {
		server := app.PrimaryDNSServer(app.ACMEConfig.Client.DNSServer)
		app.Logger.Info("ACME using DNS resolver", "server", server)
	} else if serviceRegistry := app.ServiceRegistry(); serviceRegistry != nil {
		// Fall back to the running DNS service resolver
		if dnsService := serviceRegistry.DNSService(); dnsService != nil {
			app.Logger.Debug("ACME using platform DNS service resolver")
			dnsResolver = dnsService.Resolver()
		}
	}

	if dnsResolver == nil {
		app.Logger.Warn("ACME client will use system DNS resolver - internal domains may not resolve!")
	}

	// Create the ACME client via the go-quicbaas SDK ACME re-export.
	client, err := trustedca.NewACMEClient(&trustedca.ACMEClientParams{
		AccountEmail:       accountEmail,
		AccountSigner:      signer,
		Config:             clientConfig,
		Logger:             app.Logger.Slog(),
		Storage:            accountDAO,
		CertificateStorage: certDAO,
		OrderStorage:       nil, // Created later with valid account ID
	})
	if err != nil {
		return err
	}
	app.ACMEClient = client

	// Only register account if both initialize=true AND config.register=true
	// The server uses its own ACME client to obtain TLS certificates from its own CA (self-referential)
	// Registration requires the webservice to be running to serve the ACME endpoints
	if initialize && app.ACMEConfig.Client.Account != nil && app.ACMEConfig.Client.Account.Register {
		if _, err := app.ACMEClient.RegisterAccount(); err != nil {
			return err
		}
	}

	// Handle cross-signer if configured
	primaryWS := app.PrimaryWebService()
	if primaryWS != nil && primaryWS.Certificate.ACME != nil &&
		primaryWS.Certificate.ACME.CrossSign != nil &&
		app.ACMEConfig != nil && app.ACMEConfig.Client != nil &&
		app.ACMEConfig.Client.Account != nil &&
		app.ACMEConfig.Client.Account.Register {

		xsigner, err := trustedca.ACMECrossSignerFromClient(
			app.ACMEClient, primaryWS.Certificate.ACME.CrossSign)
		if err != nil {
			return err
		}
		if initialize {
			if _, err = xsigner.RegisterAccount(); err != nil {
				app.Logger.Warn(err.Error())
			}
		}
	}
	return nil
}

// Initializes a new ACME cross-signer client using the account email
// provided in the platform configuration.
func (app *App) NewACMECrossSigner(crossSigner *trustedca.ACMECrossSignConfig, initialize bool) (*trustedca.ACMEClient, error) {
	if app.ACMEConfig == nil {
		return nil, nil
	}
	if app.ACMEClient == nil {
		return nil, trustedca.ACMEErrInvalidConfiguration
	}
	client, err := trustedca.ACMECrossSignerFromClient(app.ACMEClient, crossSigner)
	if err != nil {
		return nil, err
	}
	if initialize {
		if _, err := client.RegisterAccount(); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// Provisions the TPM per the platform configuration file and
// TCG provisioning guidance. This operation assumes a new
// TPM whose hierarchy authorizations are empty. This function
// clears the TPM, set's the hierarchy authorizations, creates
// a persistent EK, Shared SRK, and if configured, an IAK and
// IDevID in accordance with TCG and IEEE 802.1 AR for secure
// device identification and authentication.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
// exportCertToDisk writes a PEM-encoded certificate to {PlatformDir}/<name>
// with 0644 permissions so operators can inspect IAK / IDevID certs without
// going through the CA API.
func (app *App) exportCertToDisk(name string, cert *x509.Certificate) error {
	if app.PlatformDir == "" || cert == nil {
		return nil
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	dest := filepath.Join(app.PlatformDir, name)
	if err := os.WriteFile(dest, pemBytes, 0o644); err != nil {
		return err
	}
	app.Logger.Info("enrollment: exported cert to disk",
		slog.String("path", dest),
		slog.String("subject", cert.Subject.CommonName))
	return nil
}

func (app *App) ProvisionPlatform(
	ctx context.Context,
	soPIN, userPIN xkmssdk.Password,
	initParams *AppInitParams) (*xkmssdk.KeyAttributes, error) {

	app.Logger.Debug("Provisioning TPM 2.0")

	// Provision the TPM — this sets Lockout/Endorsement/Owner hierarchy
	// auth to soPIN. After this call, the TPM owner hierarchy is
	// authenticated with soPIN, NOT the empty default.
	if err := app.TPM.Provision(soPIN); err != nil {
		return nil, err
	}

	// Reflect the post-Provision TPM state in TPMConfig.SSRK so that
	// InitPlatformKeyStore's auth branch decides to pass soPIN/userPIN
	// to ks.Initialize(). Without this, it sees SSRK.HierarchyAuth=""
	// and calls InitializeWithDefaults() which passes empty auth to
	// TPM2_Create under the OWNER hierarchy → TPM_RC_BAD_AUTH.
	if app.TPMConfig.SSRK == nil {
		app.TPMConfig.SSRK = &xkmssdk.SRKConfig{}
	}
	app.TPMConfig.SSRK.HierarchyAuth = string(soPIN.Bytes())
	// Mirror for EK — Provision() also sets the ENDORSEMENT hierarchy
	// auth to soPIN. Any downstream CreatePrimary under EH (e.g. the
	// IDevID key minted during ACME enroll-01 challenge setup) must
	// authenticate the hierarchy with soPIN, otherwise the TPM rejects
	// the primary-key create with TPM_RC_BAD_AUTH. Without this, the
	// enrollment ceremony aborts at "failed to create IDevID primary
	// key" even though the account + order were successfully created.
	if app.TPMConfig.EK == nil {
		app.TPMConfig.EK = &xkmssdk.EKConfig{}
	}
	app.TPMConfig.EK.HierarchyAuth = string(soPIN.Bytes())

	// Provision the platform TPM 2.0 key store
	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		return nil, err
	}

	// Initialize the Certificate Authorities
	if app.CAConfig != nil {
		if _, err := app.InitCA(ctx, soPIN, userPIN, initParams); err != nil {
			return nil, err
		}
	}

	// Initialize the ACME client if configured
	if app.ACMEClient == nil && app.ACMEConfig != nil && app.ACMEConfig.Client != nil {
		// Check if any webservice has an ACME server with the same directory URL as the client
		// This indicates self-referential operation where the ACME client uses the local ACME server
		selfReferential := false
		for _, ws := range app.WebServices {
			if ws.ACME != nil && ws.ACME.Enabled && ws.ACME.DirectoryURL == app.ACMEConfig.Client.DirectoryURL {
				selfReferential = true
				app.Logger.Info("Detected self-referential ACME configuration",
					"client_directory", app.ACMEConfig.Client.DirectoryURL,
					"webservice", ws.Name)
				break
			}
		}

		if selfReferential {
			// Skip ACME client initialization when self-referential (client directory URL
			// matches a local webservice's ACME server). The webservice needs to bootstrap
			// first before the ACME client can request/renew certificates from itself.
			app.Logger.Info("Skipping ACME client init during provisioning (self-referential)")
		} else {
			// External ACME server - initialize client now.
			// Try first without trust bootstrap — the CA bundle may already be in
			// the OS trust store (e.g., installed by the trusted-platform ISO
			// installer or platform-initrd). Only fall back to BootstrapTrust when
			// the initial attempt fails, which covers non-trusted OS environments.
			if err := app.InitACMEClient(ctx, true); err != nil {
				app.Logger.Warn("ACME client init failed, attempting trust bootstrap",
					"error", err)
				if bsErr := app.BootstrapTrust(ctx); bsErr != nil {
					app.Logger.Error(bsErr, "Trust bootstrap also failed")
					return nil, &CommandOutputError{Msg: "ACME client init failed", Err: err, Detail: fmt.Sprintf(" (bootstrap: %v)", bsErr)}
				}
				// Retry after bootstrap installed the server CA bundle
				if err := app.InitACMEClient(ctx, true); err != nil {
					return nil, err
				}
			}
		}
	}

	// Imports the TPM Endorsement Key into the Certificate Authority
	ekCert, err := app.ImportEndorsementKeyCertificate(ctx)
	if err != nil {
		return nil, err
	}

	policyDigest, policyErr := app.TPM.PlatformPolicyDigest()
	if policyErr != nil {
		return nil, policyErr
	}
	idevidAttrs, err := xkmssdk.IDevIDAttributesFromConfig(
		*app.TPMConfig.IDevID, &policyDigest)
	if err != nil {
		return nil, err
	}

	// Create IAK & IDevID keys and certificates
	if app.TPMConfig.IAK != nil && app.TPMConfig.IDevID != nil {

		// If an ACME client configuration is provided with an
		// enrollment challenge, enroll the device with the OEM
		// Enterprise / Privacy CA.
		if app.ACMEConfig != nil && app.ACMEConfig.Client != nil &&
			app.ACMEConfig.Client.Enrollment != nil {

			if app.ACMEClient == nil {
				if err := app.InitACMEClient(ctx, initParams.Initialize); err != nil {
					return nil, err
				}
			}

			// Create context with timeout for enrollment
			enrollCtx, cancelEnroll := context.WithTimeout(ctx, 5*time.Minute)
			defer cancelEnroll()
			// Convert YAML enrollment config to runtime enrollment config
			// Wrap go-xkms's TPM with the ACME client adapter

			// Resolve ${PREFERRED_IP} macro before passing to go-trusted-ca
			// go-trusted-ca accepts plain IP addresses
			enrollmentIP := app.ACMEConfig.Client.Enrollment.IPAddress
			if enrollmentIP == "${PREFERRED_IP}" {
				enrollmentIP = util.PreferredIPv4().String()
				app.Logger.Info("Resolved PREFERRED_IP for ACME enrollment", "ip", enrollmentIP)
			}

			enrollConfig := &trustedca.ACMEEnrollmentConfig{
				Challenge:  app.ACMEConfig.Client.Enrollment.Challenge,
				IPAddress:  enrollmentIP,
				TPMModule:  trustedca.NewACMEXKMSTPMAdapter(app.TPM),
				CommonName: app.Hostname,
			}
			enrollResult, err := app.ACMEClient.EnrollDevice(enrollCtx, enrollConfig)
			if err != nil {
				return nil, err
			}

			// Import the IAK certificate from ACME enrollment
			if enrollResult.IAKCertificate != nil {
				app.Logger.Info("Importing IAK certificate from ACME enrollment",
					slog.String("subject", enrollResult.IAKCertificate.Subject.CommonName))
				if err := app.CA.ImportCertificate(ctx, enrollResult.IAKCertificate); err != nil {
					app.Logger.Error(err, slog.String("context", "Failed to import IAK certificate"))
				}
				fmt.Println("IAK Certificate:")
				fmt.Println(localcertstore.ToString(enrollResult.IAKCertificate))
			}

			// Import the IDevID certificate from ACME enrollment
			if enrollResult.IDevIDCertificate != nil {
				app.Logger.Info("Importing IDevID certificate from ACME enrollment",
					slog.String("subject", enrollResult.IDevIDCertificate.Subject.CommonName))
				if err := app.CA.ImportCertificate(ctx, enrollResult.IDevIDCertificate); err != nil {
					app.Logger.Error(err, slog.String("context", "Failed to import IDevID certificate"))
				}
				fmt.Println("IDevID Certificate:")
				fmt.Println(localcertstore.ToString(enrollResult.IDevIDCertificate))

				// Perform post-enrollment provisioning: fetch profile and activate
				// This uses mTLS with the IDevID certificate to authenticate
				profile, activateResp, provErr := app.FetchProfileAndActivate(ctx, enrollResult.IDevIDCertificate)
				if provErr != nil {
					app.Logger.Warn("Post-enrollment provisioning failed (non-fatal)",
						slog.String("error", provErr.Error()))
				} else if profile != nil && activateResp != nil {
					app.Logger.Info("Post-enrollment provisioning completed",
						slog.String("serial", profile.SerialNumber),
						slog.Int("production_vlan", int(profile.TrustedNetwork.VLAN)),
						slog.String("activation_status", activateResp.Status))
				}
			}

		} else { // No ACME client config, create IAK and IDevID certificates using local CA

			// ekAttrs, err := app.TPM.EKAttributes()
			// if err != nil {
			// 	return nil, err
			// }

			iakAttrs, err := app.TPM.IAKAttributes()
			if err != nil {
				return nil, err
			}

			// Provision IDevID Key
			var tcgCSRIDevID *xkmssdk.TCG_CSR_IDEVID
			idevidAttrs, tcgCSRIDevID, err = app.TPM.CreateIDevID(iakAttrs, ekCert, nil)
			if err != nil {
				return nil, err
			}
			xkmssdk.DebugKeyAttributes(app.Logger.Slog(), idevidAttrs)

			// Pack the TCG_CSR_IDEVID to bytes for verification
			packedCSR, err := xkmssdk.PackIDevIDCSR(tcgCSRIDevID)
			if err != nil {
				return nil, &WrappedError{Msg: "failed to pack TCG_CSR_IDEVID", Err: err}
			}

			// Verify the TCG_CSR_IDEVID and receive the encrypted challenge
			credentialBlob, encryptedSecret, secret, err := app.CA.VerifyTCG_CSR_IDevIDBytes(
				packedCSR, iakAttrs.SignatureAlgorithm)
			if err != nil {
				return nil, err
			}

			// Release the secret using TPM2_ActivateCredential and
			// verify the secrets match
			releasedCertInfo, err := app.TPM.ActivateCredential(
				credentialBlob, encryptedSecret)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(releasedCertInfo, secret) {
				return nil, xkmssdk.ErrTPMInvalidActivationCredential
			}

			// Resolve zone extensions for the platform's own self-IDevID when
			// encode_zone_in_cert is enabled in the SDN identity config.
			var sdnIdentityCfg *sdn.IdentityConfig
			if app.SDNConfig != nil {
				sdnIdentityCfg = app.SDNConfig.Identity
			}
			zoneExts, zoneErr := sdn.BuildNetworkZoneExtensions(
				sdnIdentityCfg,
				sdnIdentityCfg.ResolvedPlatformZone(),
				app.Hostname,
			)
			if zoneErr != nil {
				return nil, zoneErr
			}

			// Sign TCG_CSR_IDEVID, create IDevID x509 device certificate
			iakDER, idevidDER, err := app.CA.SignTCGCSRIDevID(ctx, tcgCSRIDevID, &quicbaasca.CACertificateRequest{
				// KeyAttributes: ekAttrs,
				KeyAttributes:   idevidAttrs,
				Valid:           0, // Valid until 99991231235959Z
				ExtraExtensions: zoneExts,
				Subject: quicbaasca.CASubject{
					CommonName:   idevidAttrs.CN,
					Organization: app.PrimaryWebService().Certificate.Subject.Organization,
					Country:      app.PrimaryWebService().Certificate.Subject.Country,
					Locality:     app.PrimaryWebService().Certificate.Subject.Locality,
					Address:      app.PrimaryWebService().Certificate.Subject.Address,
					PostalCode:   app.PrimaryWebService().Certificate.Subject.PostalCode,
				},
				SANS: &quicbaasca.CASubjectAlternativeNames{
					DNS: []string{
						app.Domain,
					},
					IPs: []string{},
					Email: []string{
						app.Hostmaster,
					},
				},
			})
			if err != nil {
				return nil, err
			}

			// Import the IAK certificate
			iakCert, err := x509.ParseCertificate(iakDER)
			if err != nil {
				return nil, err
			}
			if err := app.CA.ImportCertificate(ctx, iakCert); err != nil {
				return nil, err
			}

			// Import the IDevID certificate
			idevidCert, err := x509.ParseCertificate(idevidDER)
			if err != nil {
				return nil, err
			}
			if err := app.CA.ImportCertificate(ctx, idevidCert); err != nil {
				return nil, err
			}

			// Perform local TPM Quote and store attestation
			quote, nonce, err := app.AttestLocal(iakAttrs)
			if err != nil {
				return nil, &WrappedError{Msg: "failed to perform local attestation", Err: err}
			}

			// Verify the quote and import attestation data
			if err := app.VerifyLocalQuote(ctx, iakAttrs, quote, nonce); err != nil {
				return nil, &WrappedError{Msg: "failed to verify local quote", Err: err}
			}
		}
	}

	if err := app.InitWebServer(ctx); err != nil {
		return nil, err
	}

	return idevidAttrs, nil
}

// FetchProfileAndActivate performs the post-ACME-enrollment provisioning flow:
// 1. Creates an mTLS client using the IDevID certificate
// 2. Fetches the device profile from the provisioning server
// 3. Signals activation readiness for network transition
//
// This should be called after ACME enrollment completes and the IDevID certificate
// is available. The provisioning server is derived from the ACME directory URL.
//
// Returns the profile and activation response, or an error if provisioning fails.
func (app *App) FetchProfileAndActivate(
	ctx context.Context,
	idevidCert *x509.Certificate,
) (*provisioning.ProfileResponse, *provisioning.ActivateResponse, error) {

	if idevidCert == nil {
		return nil, nil, provisioning.ErrMissingCertificate
	}

	// Get the provisioning server URL from ACME config
	// The provisioning API is on the same server as ACME
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil || app.ACMEConfig.Client.DirectoryURL == "" {
		app.Logger.Warn("ACME client not configured, skipping provisioning")
		return nil, nil, nil
	}

	// Extract base URL from ACME directory URL
	// e.g., "https://server.example.com:8443/acme/directory" -> "https://server.example.com:8443"
	serverURL, err := util.ExtractBaseURL(app.ACMEConfig.Client.DirectoryURL)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to extract server URL from ACME directory", Err: err}
	}

	app.Logger.Info("Starting post-enrollment provisioning",
		slog.String("server", serverURL),
		slog.String("idevid_cn", idevidCert.Subject.CommonName))

	// Get IDevID key attributes for TPM signing
	idevidAttrs, err := app.TPM.IDevIDAttributes()
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to get IDevID key attributes", Err: err}
	}

	// Create TPM signer for IDevID key
	tpmSigner := platform.NewTPMSigner(
		app.TPM,
		idevidAttrs,
		app.PlatformKS.Backend(),
	)

	// Get CA certificate pool for server verification.
	// TLS verification is mandatory — the platform cannot provision securely
	// without a trusted root certificate pool.
	rootCert, err := app.CA.RootCertificate(idevidCert)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to get root certificate for IDevID", Err: err}
	}
	caPool, err := app.CA.TrustedRootCertPool(rootCert)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to get trusted root cert pool", Err: err}
	}

	// Create provisioning client config
	provConfig := &provisioning.ClientConfig{
		ServerURL:   serverURL,
		Certificate: idevidCert,
		PrivateKey:  tpmSigner, // crypto.Signer is compatible with crypto.PrivateKey
		CACertPool:  caPool,
		Timeout:     30 * time.Second,
	}

	// Create provisioning client
	provClient, err := provisioning.NewClient(provConfig, app.Logger)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "failed to create provisioning client", Err: err}
	}
	defer provClient.Close()

	// Fetch profile and activate
	profile, activateResp, err := provClient.FetchProfileAndActivate(ctx)
	if err != nil {
		return nil, nil, &WrappedError{Msg: "provisioning failed", Err: err}
	}

	app.Logger.Info("Device provisioning complete",
		slog.String("serial", profile.SerialNumber),
		slog.Int("vlan", int(profile.TrustedNetwork.VLAN)),
		slog.String("status", activateResp.Status))

	return profile, activateResp, nil
}

// Import TPM Endorsement Certificate - EK Credential Profile. Attempts
// to import the EK certificate from the TPM into the CA. If an EK
// certificate is not found, and the ek-gen options are set in the
// platform configuration file, a new EK certificate will be generated
// and imported into the TPM or certificate store. If the ACME client
// is configured, the EK certificate is requested from the Enterprise CA,
// otherwise, the EK certificate is generated using the local CA.
func (app *App) ImportEndorsementKeyCertificate(ctx context.Context) (*x509.Certificate, error) {

	if app.CAConfig == nil {
		return nil, ErrMissingEKWithoutEnabledCA
	}

	ekAttrs, err := app.TPM.EKAttributes()
	if err != nil {
		return nil, err
	}

	ekCert, err := app.TPM.EKCertificate()
	if err != nil {

		if err == xkmssdk.ErrTPMEndorsementCertNotFound {

			var publicKey crypto.PublicKey

			if app.TPMConfig.EK.KeyAlgorithm == x509.RSA.String() {
				rsaKey, rsaErr := app.TPM.EKRSA()
				if rsaErr != nil {
					return nil, rsaErr
				}
				publicKey = rsaKey
			} else if app.TPMConfig.EK.KeyAlgorithm == x509.ECDSA.String() {
				eccKey, eccErr := app.TPM.EKECC()
				if eccErr != nil {
					return nil, eccErr
				}
				publicKey = eccKey
			} else {
				app.Logger.Errorf(
					"unsupported TPM EK algorithm %s",
					app.TPMConfig.EK.KeyAlgorithm)
				return nil, xkmssdk.ErrInvalidKeyAlgorithm
			}

			certReq := quicbaasca.CACertificateRequest{
				KeyAttributes: ekAttrs,
				Subject: quicbaasca.CASubject{
					CommonName:   ekAttrs.CN,
					Organization: app.PrimaryWebService().Certificate.Subject.Organization,
					Country:      app.PrimaryWebService().Certificate.Subject.Country,
					Locality:     app.PrimaryWebService().Certificate.Subject.Locality,
					Address:      app.PrimaryWebService().Certificate.Subject.Address,
					PostalCode:   app.PrimaryWebService().Certificate.Subject.PostalCode,
				},
				SANS: &quicbaasca.CASubjectAlternativeNames{
					DNS: []string{
						app.Domain,
					},
					IPs: []string{},
					Email: []string{
						app.Hostmaster,
					},
				},
			}

			// Check if ACME client is configured with enrollment - if so, request
			// the EK certificate from the Enterprise CA using the endorse-01 challenge.
			// This is the proper flow for devices without manufacturer EK certificates
			// (e.g., swtpm, virtual TPMs, or custom enterprise provisioning).
			if app.ACMEClient != nil && app.ACMEConfig != nil &&
				app.ACMEConfig.Client != nil && app.ACMEConfig.Client.Enrollment != nil {

				app.Logger.Info("Requesting EK certificate from Enterprise CA via endorse-01")

				// Resolve IP address macro before passing to ACME client
				enrollmentIP := app.ACMEConfig.Client.Enrollment.IPAddress
				if enrollmentIP == "${PREFERRED_IP}" {
					enrollmentIP = util.PreferredIPv4().String()
					app.Logger.Info("Resolved PREFERRED_IP for endorse-01 enrollment", "ip", enrollmentIP)
				}

				// Create context with timeout for EK certificate request
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				// Request EK certificate from Enterprise CA using endorse-01 challenge
				ekConfig := &trustedca.ACMEEnrollmentConfig{
					Challenge:  "endorse-01",
					IPAddress:  enrollmentIP,
					TPMModule:  trustedca.NewACMEXKMSTPMAdapter(app.TPM),
					CommonName: app.Hostname,
				}
				ekCert, err = app.ACMEClient.RequestEndorsementKeyCertificate(ctx, ekConfig)
				if err != nil {
					return nil, &WrappedError{Msg: "failed to request EK certificate via endorse-01", Err: err}
				}
				app.Logger.Info("EK certificate obtained from Enterprise CA")
			} else {
				// Generate new Endorsement Key x509 Certificate using the local CA and save
				// the certificate to blob storage.
				ekCert, err = app.CA.IssueEKCertificate(ctx, &certReq, publicKey)
				if err != nil {
					return nil, err
				}
			}
			fmt.Println(xkmssdk.CertToString(ekCert))

			// Write the EK cert to TPM NV RAM
			// Get hierarchy auth from config since ekAttrs from KeyAttributes() doesn't include it
			var hierarchyAuth []byte
			if app.TPMConfig.EK.HierarchyAuth != "" {
				hierarchyAuth = []byte(app.TPMConfig.EK.HierarchyAuth)
			} else if ekAttrs.TPMAttributes != nil && ekAttrs.TPMAttributes.HierarchyAuth != nil {
				hierarchyAuth = ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
			}

			if err := app.TPM.ProvisionEKCert(hierarchyAuth, ekCert.Raw); err != nil {
				// NOTE: TPM simulator throws an error here for certs
				// greater than 1024 bytes. To work around this, a warning
				// is emitted and the cert-handle attribute is ignored so
				// the certificate can be imported to the certificate store
				// instead of TPM NV RAM.
				if len(ekCert.Raw) > 1024 && app.TPMConfig.UseSimulator {
					if app.TPMConfig.EK.CertHandle > 0 {
						app.Logger.Warn(warnSimulatorWithEKCertHandle.Error())
					}
					// Fall back to saving EK cert in TPM's certificate store
					// since NVRAM write failed for simulator with large certs
					if app.TPMCertStore != nil {
						app.Logger.Info("Saving EK certificate to TPM cert store (NVRAM fallback)")
						if err := app.TPMCertStore.Save(ekAttrs, ekCert); err != nil {
							app.Logger.Errorf("Failed to save EK cert to TPM cert store: %v", err)
							return nil, &WrappedError{Msg: "failed to save EK certificate", Err: err}
						}
					} else {
						app.Logger.Warn("TPMCertStore not initialized, cannot save EK certificate")
					}
				} else {
					// NVRAM provisioning failed for non-simulator case, fall back to CA import
					app.Logger.Warnf("failed to provision EK cert to TPM NVRAM, falling back to CA import: %v", err)
					if importErr := app.CA.ImportEndorsementKeyCertificate(ekCert); importErr != nil {
						return nil, &CommandOutputError{Msg: "failed to import EK certificate after NVRAM provisioning failure", Err: importErr, Detail: fmt.Sprintf(" (original error: %v)", err)}
					}
				}
			}
			return ekCert, nil

		} else {
			return nil, err
		}
	}
	err = app.CA.ImportEndorsementKeyCertificate(ekCert)
	if err != nil {
		return nil, err
	}

	return ekCert, nil
}

// Loads an initialized Certificate Authority
func (app *App) LoadCA(ctx context.Context, soPIN, userPIN xkmssdk.Password) error {

	if len(app.CAConfig.Identity) == 0 {
		return trustedca.CAErrInvalidConfig
	}

	// Ensure SelectedCA (platform-ca) is properly set when an intermediate CA is configured
	// If SelectedCA is 0 but there's more than one identity, default to 1 (intermediate)
	if app.CAConfig.SelectedCA == 0 && len(app.CAConfig.Identity) > 1 {
		app.Logger.Debug("SelectedCA is 0 but intermediate CA exists, defaulting to 1")
		app.CAConfig.SelectedCA = 1
	}

	// Get the issuing CA identity (intermediate when SelectedCA > 0)
	issuingIdentity := app.CAConfig.Identity[app.CAConfig.SelectedCA]

	// Build CA home directory path for XKMS service
	// Uses the ISSUING CA's CommonName for backward compatibility
	caRoot := fmt.Sprintf("%s/ca/%s", app.PlatformDir, issuingIdentity.Subject.CommonName)

	// Initialize platform key store before XKMS service
	// This ensures TPM password sealing is available for keys with PlatformPolicy=true
	if app.TPM != nil && app.PlatformKS == nil {
		if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
			return &WrappedError{Msg: "failed to initialize platform key store", Err: err}
		}
	}

	// Initialize XKMS service before creating CA
	_, err := app.initXKMSService(caRoot, soPIN, userPIN)
	if err != nil {
		return &WrappedError{Msg: "failed to initialize XKMS service", Err: err}
	}

	// Native pkg/ca has no LazyInitialization / ParseKeyAlgorithms surface:
	// MultiIdentityCAConfig.Identity[*].Keys[*].KeyAlgorithm is a typed string
	// on the wire and is parsed automatically during Load/Init. This path
	// always corresponds to "load existing CA" semantics (Lazy=true in the
	// legacy wrapper); callers that want fresh initialization use InitCA
	// instead.

	// Create per-CA store factory. Separate keystores, certstores and
	// objectstores per CA (root, intermediate) at platformDir/ca/<ca-cn>/.
	storeFactory := NewCAStoreFactory(app, app.PlatformDir, app.Storage, soPIN, userPIN)

	// Build the issuing CA from params.Identity via the native NewCA
	// constructor (root + optional intermediate) and select the appropriate
	// TrustedCA per config.SelectedCA. The returned CAs are uninitialized
	// when built via NewParentCA/NewIntermediateCA directly, so we route
	// through NewCA which auto-initializes both. We then re-load from
	// storage via Load() to match the "lazy" (load existing) contract of
	// this function.
	root, intermediate, err := quicbaasca.NewCA(ctx, &quicbaasca.Params{
		Identity:           app.CAConfig.Identity,
		KeyStoreFactory:    keyStoreFactoryAdapter(storeFactory),
		CertStoreFactory:   certStoreFactoryAdapter(storeFactory),
		ObjectStoreFactory: objectStoreFactoryAdapter(storeFactory),
	})
	if err != nil {
		return &WrappedError{Msg: "failed to create CA", Err: err}
	}

	caInstance := selectIssuingCA(app.CAConfig, root, intermediate)
	if caInstance == nil {
		return &MessageError{Msg: "failed to select issuing CA from multi-identity config"}
	}

	// Load existing CA from storage to honor the "load existing" contract
	// previously expressed via LazyInitialization=true. Errors here are
	// surfaced to the caller so misconfigured deployments fail fast.
	if err := caInstance.Load(ctx); err != nil {
		return &WrappedError{Msg: "failed to load CA", Err: err}
	}

	// Set TPM for enrollment operations
	if tcg, ok := caInstance.(quicbaasca.TCGCA); ok && app.TPM != nil {
		tcg.SetTPM(app.TPM)
	}

	app.CA = mustTCGCA(caInstance)
	return nil
}

// Initializes all Certificate Authorities provided in the
// platform configuration file and returns the selected
// "Platform CA" as the default CA used for Platform operations.
func (app *App) InitCA(ctx context.Context, soPIN, userPIN xkmssdk.Password, initParams *AppInitParams) (quicbaasca.CACertificateAuthority, error) {

	if app.TPM == nil {
		if err := app.OpenTPM(initParams.Initialize); err != nil {
			// TPM not available - continue without it for software-only CA keystores.
			// If the CA config requires TPM-based keystores, it will fail during
			// key creation with a clear error message.
			app.Logger.Warn("TPM not available for CA initialization (software-only CA will work)",
				"error", err)
		}
	}

	if len(app.CAConfig.Identity) == 0 {
		return nil, trustedca.CAErrInvalidConfig
	}

	// Set the selected CA index (use intermediate by default if available)
	app.CAConfig.SelectedCA = initParams.PlatformCA
	if app.CAConfig.SelectedCA == 0 && len(app.CAConfig.Identity) > 1 {
		app.CAConfig.SelectedCA = 1
	}

	// Get the issuing CA identity (intermediate when SelectedCA > 0)
	issuingIdentity := app.CAConfig.Identity[app.CAConfig.SelectedCA]

	// Build CA home directory path for XKMS service
	// Uses the ISSUING CA's CommonName for backward compatibility
	caRoot := fmt.Sprintf("%s/ca/%s", app.PlatformDir, issuingIdentity.Subject.CommonName)

	// Initialize platform key store before XKMS service
	// This ensures TPM password sealing is available for keys with PlatformPolicy=true
	if app.TPM != nil && app.PlatformKS == nil {
		if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
			return nil, &WrappedError{Msg: "failed to initialize platform key store", Err: err}
		}
	}

	// Initialize XKMS service
	_, err := app.initXKMSService(caRoot, soPIN, userPIN)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to initialize XKMS service", Err: err}
	}

	// Set HomeDir in config
	app.CAConfig.HomeDir = app.PlatformDir

	// Native pkg/ca has no LazyInitialization toggle: NewCA() auto-initializes
	// both root and intermediate. This function's contract is "initialize or
	// reuse", matching the legacy wrapper's Lazy=false path.

	// Create per-CA store factory (separate keystores/certstores/objectstores
	// per CA CN at platformDir/ca/<cn>/).
	storeFactory := NewCAStoreFactory(app, app.PlatformDir, app.Storage, soPIN, userPIN)

	root, intermediate, err := quicbaasca.NewCA(ctx, &quicbaasca.Params{
		Identity:           app.CAConfig.Identity,
		KeyStoreFactory:    keyStoreFactoryAdapter(storeFactory),
		CertStoreFactory:   certStoreFactoryAdapter(storeFactory),
		ObjectStoreFactory: objectStoreFactoryAdapter(storeFactory),
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create CA", Err: err}
	}

	caInstance := selectIssuingCA(app.CAConfig, root, intermediate)
	if caInstance == nil {
		return nil, &MessageError{Msg: "failed to select issuing CA from multi-identity config"}
	}

	// Set TPM for enrollment operations (TCG operations require TPM wiring).
	if tcg, ok := caInstance.(quicbaasca.TCGCA); ok && app.TPM != nil {
		tcg.SetTPM(app.TPM)
	}

	tcgCA := mustTCGCA(caInstance)
	app.CA = tcgCA

	return tcgCA, nil
}

// Performs a local TPM 2.0 attestation
func (app *App) AttestLocal(serverAttrs *xkmssdk.KeyAttributes) (xkmssdk.Quote, []byte, error) {
	fmt.Println("Performing local attestation")
	quote, nonce, err := app.TPM.PlatformQuote(serverAttrs)
	if err != nil {
		return xkmssdk.Quote{}, nil, err
	}
	return quote, nonce, nil
}

// Verifies a local TPM 2.0 quote
func (app *App) VerifyLocalQuote(
	ctx context.Context,
	akAttrs *xkmssdk.KeyAttributes,
	quote xkmssdk.Quote,
	nonce []byte) error {

	if err := app.CA.VerifyQuote(akAttrs, &quote, nonce); err != nil {
		// DEFERRED: Re-seal the CA, run intrusion detection handlers,
		// wipe the file system, etc. Blocked by: intrusion detection subsystem not yet designed.
		return &SentinelCauseError{Sentinel: ErrInvalidLocalAttestationSignature, Cause: err}
	}

	if err := app.CA.ImportLocalAttestation(ctx, akAttrs, &quote); err != nil {
		return &WrappedError{Msg: "failed to import local attestation", Err: err}
	}

	return nil
}

// keyStoreFactoryAdapter wraps a *CAStoreFactory (which returns interface{})
// into the native pkg/ca.KeyStoreFactoryFunc signature expected by pkg/ca.Params.
// The adapter performs a type assertion to the xkms.Backend interface so that
// shape mismatches fail fast at the factory boundary rather than during key
// operations later.
func keyStoreFactoryAdapter(f *CAStoreFactory) quicbaasca.KeyStoreFactoryFunc {
	return func(cn string) (xkmsbackend.Backend, error) {
		result, err := f.CreateKeyStore(cn)
		if err != nil {
			return nil, err
		}
		ks, ok := result.(xkmsbackend.Backend)
		if !ok {
			return nil, &MessageError{Msg: fmt.Sprintf("key store factory returned %T, want xkms.Backend", result)}
		}
		return ks, nil
	}
}

// certStoreFactoryAdapter wraps a *CAStoreFactory into pkg/ca.CertStoreFactoryFunc.
func certStoreFactoryAdapter(f *CAStoreFactory) quicbaasca.CertStoreFactoryFunc {
	return func(cn string) (xkmscertstore.CertStore, error) {
		result, err := f.CreateCertStore(cn)
		if err != nil {
			return nil, err
		}
		cs, ok := result.(xkmscertstore.CertStore)
		if !ok {
			return nil, &MessageError{Msg: fmt.Sprintf("cert store factory returned %T, want certstore.CertStore", result)}
		}
		return cs, nil
	}
}

// objectStoreFactoryAdapter wraps a *CAStoreFactory into pkg/ca.ObjectStoreFactoryFunc.
// Returning (nil, nil) is a valid "no object store for this CA" signal per
// pkg/ca semantics, so assertion failures are surfaced as errors.
func objectStoreFactoryAdapter(f *CAStoreFactory) quicbaasca.ObjectStoreFactoryFunc {
	return func(cn string) (xkmssdk.ObjectStorage, error) {
		result, err := f.CreateObjectStore(cn)
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, nil
		}
		os, ok := result.(xkmssdk.ObjectStorage)
		if !ok {
			return nil, &MessageError{Msg: fmt.Sprintf("object store factory returned %T, want ObjectStorage", result)}
		}
		return os, nil
	}
}

// selectIssuingCA returns the TrustedCA that corresponds to config.SelectedCA.
// For single-identity configurations the root is returned; for root+intermediate
// configurations the intermediate is returned when SelectedCA != 0 and
// intermediate is non-nil.
func selectIssuingCA(cfg *trustedca.CAConfig, root, intermediate quicbaasca.TrustedCA) quicbaasca.TrustedCA {
	if cfg == nil {
		return nil
	}
	if cfg.SelectedCA > 0 && intermediate != nil {
		return intermediate
	}
	return root
}

// mustTCGCA narrows a TrustedCA to its TCGCA interface. The native pkg/ca
// constructors return TrustedCA even though the concrete type implements
// TCGCA; this helper performs the assertion and returns nil when the
// underlying type does not support TCG operations.
func mustTCGCA(ca quicbaasca.TrustedCA) quicbaasca.CACertificateAuthority {
	if tcg, ok := ca.(quicbaasca.TCGCA); ok {
		return tcg
	}
	return nil
}

// isCertNotFoundError returns true if the error indicates a certificate was
// not found. Checks for trustedca.CAErrCertificateNotFound which is the canonical
// sentinel returned by the CA layer for missing certificates.
func isCertNotFoundError(err error) bool {
	return errors.Is(err, trustedca.CAErrCertificateNotFound)
}

// InitWebServer starts the embedded web server. When the initialize parameter is true,
// the web server's TLS certificate configuration is used to generate a new
// pre-configured TLS cert for the web server. If the common name matches the
// common name of the IDevID key attributes, then the IDevID key is used to generate
// the TLS certificate, otherwise, a new key will be generated whose common name
// matches the common name configured in the web server's TLS certificate configuration.
// If an ACME client section has been provided in the platform configuration,
// the ACME directory specified in this block will be used to sign the generated CSR.
// If an ACME cross-sign configuration is also present in the certificate configuration,
// the ACME directory provided in the cross-signing configuration will be used to
// cross-sign the certificate.
func (app *App) InitWebServer(ctx context.Context) error {

	if len(app.WebServices) == 0 {
		app.Logger.Warn("web services disabled")
		return nil
	}

	// Check if PlatformKS is available - required for webservice TLS certificates
	if app.PlatformKS == nil {
		app.Logger.Warn("PlatformKS not available - web services cannot be initialized without TPM platform keystore")
		app.Logger.Warn("This is expected during initial provisioning. Web services will be available after TPM is provisioned.")
		return nil
	}

	app.Logger.Info("Initializing web services")

	// Initialize the map to store key attributes for each webservice
	app.WebServiceKeyAttributes = make(map[string]*xkmssdk.KeyAttributes)

	// Process each webservice
	for _, wsConfig := range app.WebServices {
		wsName := wsConfig.Name
		if wsName == "" {
			wsName = "default"
		}

		if err := app.initWebServiceKeyAttributes(ctx, wsConfig); err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to initialize webservice %s", wsName), Err: err}
		}
	}

	return nil
}

// initWebServiceKeyAttributes initializes the key attributes and TLS certificate
// for a single webservice. This is called for each configured webservice.
func (app *App) initWebServiceKeyAttributes(ctx context.Context, wsConfig *v1.Config) error {
	wsName := wsConfig.Name
	if wsName == "" {
		wsName = "default"
	}

	app.Logger.Info("Initializing webservice", "name", wsName, "cn", wsConfig.Certificate.Subject.CommonName)

	var keyAttrs *xkmssdk.KeyAttributes

	// Check if this webservice should use the IDevID certificate. This
	// activates when tpm.idevid.cn matches the webservice CN and an IDevID
	// has been provisioned (by enroll-01 during ProvisionPlatform, or a
	// prior firstboot TPM setup). When the IDevID hasn't been provisioned
	// yet — common on first boot before platformd has run its TPM setup,
	// or when TPM state was cleared — IDevIDAttributes returns
	// TPM_RC_HANDLE. Fall through to the dedicated-webservice-key path
	// rather than hard-failing; the platform's local CA still issues a
	// valid cert and ACME enrollment can complete on a later boot.
	idevidReuseRequested := app.TPMConfig.IDevID != nil &&
		app.TPMConfig.IDevID.CN == wsConfig.Certificate.Subject.CommonName
	if idevidReuseRequested {
		idevidAttrs, err := app.TPM.IDevIDAttributes()
		if err == nil {
			app.Logger.Info("using IDevID certificate for TLS", "webservice", wsName)
			if app.TPMConfig.IDevID.Handle != 0 {
				idevidAttrs.TPMAttributes.HandleType = libtpm2.TPMHTPersistent
			}
			idevidAttrs.KeyType = xkmssdk.KeyTypeIDevID
			keyAttrs = idevidAttrs
		} else {
			app.Logger.Warn("IDevID not yet provisioned — falling back to dedicated webservice key",
				"webservice", wsName, "err", err.Error())
		}
	}
	if keyAttrs == nil {
		app.Logger.Info("using dedicated web server certificate for TLS", "webservice", wsName)
		serverKeyAttrs, err := wsConfig.Key.ToKeyAttributes()
		if err != nil {
			return err
		}
		// Check if PlatformKS is available before accessing SRK attributes
		if app.PlatformKS != nil {
			serverKeyAttrs.Parent = app.PlatformKS.SRKAttributes()
		}
		if serverKeyAttrs.Parent == nil {
			err := &MessageError{Msg: "failed to get SRK attributes: TPM SSRK not available - check if TPM is properly initialized"}
			app.Logger.Error(err)
			return err
		}
		serverKeyAttrs.CN = wsConfig.Certificate.Subject.CommonName
		serverKeyAttrs.KeyType = xkmssdk.KeyTypeTLS
		serverKeyAttrs.TPMAttributes = &xkmssdk.TPMAttributes{}
		keyAttrs = serverKeyAttrs
	}
	xkmssdk.DebugKeyAttributes(app.Logger.Slog(), keyAttrs)

	// Set up PlatformPassword before any certificate operations if PlatformPolicy is enabled.
	// This is needed both for loading existing certs and creating new ones.
	var platformPassword xkmssdk.Password
	if keyAttrs.PlatformPolicy && app.TPM != nil && app.PlatformKS != nil {
		// Ensure parent SRK attributes are set
		if keyAttrs.Parent == nil {
			keyAttrs.Parent = app.PlatformKS.SRKAttributes()
		}

		// Create the platform password wrapper for TPM-sealed password access
		// IMPORTANT: Don't set keyAttrs.Password yet - Create() needs the original
		// password from config to seal it. We'll set it after Create() succeeds or
		// when loading an existing cert.
		platformPassword = xkmssdk.NewPlatformPassword(
			app.Logger.Slog(),
			app.TPM,
			keyAttrs,
			app.PlatformKS.Backend(),
		)
		app.Logger.Debug("PlatformPassword created for webservice",
			"webservice", wsName,
			"cn", keyAttrs.CN)
	}

	// Try to load the web services TLS cert
	// For existing certs, we need PlatformPassword to unseal
	if platformPassword != nil {
		// Temporarily set PlatformPassword to attempt loading existing cert
		originalPassword := keyAttrs.Password
		keyAttrs.Password = platformPassword

		app.Logger.Debug("Checking for existing TLS certificate",
			"webservice", wsName,
			"cn", keyAttrs.CN)

		_, err := app.CA.PEM(ctx, keyAttrs)
		if err == nil {
			// Cert exists and loaded successfully, keep PlatformPassword
			app.Logger.Debug("PlatformPassword configured for webservice (existing cert)",
				"webservice", wsName,
				"cn", keyAttrs.CN)
			goto certLoaded
		}

		app.Logger.Debug("Certificate lookup returned error",
			"webservice", wsName,
			"cn", keyAttrs.CN,
			"error", err.Error(),
			"error_type", fmt.Sprintf("%T", err),
			"is_cert_not_found", isCertNotFoundError(err))

		// Restore original password for Create() to use
		keyAttrs.Password = originalPassword

		// Check for cert not found error
		if !isCertNotFoundError(err) {
			// Unexpected error
			return &WrappedError{Msg: fmt.Sprintf("failed to load certificate for webservice %s", wsName), Err: err}
		}

		app.Logger.Info("Certificate not found, will issue new certificate",
			"webservice", wsName,
			"cn", keyAttrs.CN)

		// Seal password to TPM before generating keys
		if pp, ok := platformPassword.(*xkmssdk.PlatformPassword); ok {
			app.Logger.Info("Sealing webservice key password to TPM",
				"webservice", wsName,
				"cn", keyAttrs.CN)
			if err := pp.Create(); err != nil {
				// Check if error is "key already exists" - this is OK, we can reuse it
				if strings.Contains(err.Error(), "already exists") {
					app.Logger.Info("Using existing sealed password for webservice",
						"webservice", wsName,
						"cn", keyAttrs.CN)
				} else {
					return &WrappedError{Msg: fmt.Sprintf("failed to seal password to TPM for webservice %s", wsName), Err: err}
				}
			} else {
				app.Logger.Info("Password sealed to TPM for webservice",
					"webservice", wsName,
					"cn", keyAttrs.CN)
			}
			// Now set the PlatformPassword for future use
			keyAttrs.Password = platformPassword
		}
	} else {
		// No PlatformPolicy, just try to load cert normally
		app.Logger.Debug("Checking for existing TLS certificate",
			"webservice", wsName,
			"cn", keyAttrs.CN)

		_, err := app.CA.PEM(ctx, keyAttrs)
		if err == nil {
			goto certLoaded
		}

		app.Logger.Debug("Certificate lookup returned error",
			"webservice", wsName,
			"cn", keyAttrs.CN,
			"error", err.Error(),
			"error_type", fmt.Sprintf("%T", err),
			"is_cert_not_found", isCertNotFoundError(err))

		// Check for cert not found error
		if !isCertNotFoundError(err) {
			// Unexpected error
			return &WrappedError{Msg: fmt.Sprintf("failed to load certificate for webservice %s", wsName), Err: err}
		}

		app.Logger.Info("Certificate not found, will issue new certificate",
			"webservice", wsName,
			"cn", keyAttrs.CN)
	}

	// Issue new certificate
	if err := app.issueWebServiceCertificate(ctx, wsName, wsConfig, keyAttrs); err != nil {
		return err
	}

certLoaded:
	// Store the key attributes in the map
	app.WebServiceKeyAttributes[wsName] = keyAttrs
	return nil
}

// issueWebServiceCertificate issues a new TLS certificate for a webservice
func (app *App) issueWebServiceCertificate(ctx context.Context, wsName string, wsConfig *v1.Config, keyAttrs *xkmssdk.KeyAttributes) error {
	var certDER, xsignedDER []byte

	// Check if this webservice runs an ACME server
	useLocalCA := false
	if wsConfig.ACME != nil && wsConfig.ACME.Enabled {
		useLocalCA = true
		app.Logger.Info("Webservice has ACME server enabled, using local CA for TLS cert",
			"webservice", wsName,
			"acme_directory", wsConfig.ACME.DirectoryURL)
	}

	// Build SANS from webservice config
	var sans *quicbaasca.CASubjectAlternativeNames
	if wsConfig.Certificate.SANS != nil {
		sans = wsConfig.Certificate.SANS
	} else {
		sans = &quicbaasca.CASubjectAlternativeNames{
			DNS:   []string{keyAttrs.CN},
			IPs:   []string{},
			Email: []string{app.Hostmaster},
		}
	}

	// Include localhost SANS if configured
	if app.CAConfig.IncludeLocalhostSANS {
		ips, err := util.LocalAddresses()
		if err != nil {
			app.Logger.Error(err, "Failed to get local addresses for SANS", "webservice", wsName)
			return &WrappedError{Msg: fmt.Sprintf("failed to get local addresses for webservice %s SANS", wsName), Err: err}
		}
		sans.DNS = append(sans.DNS, "localhost", "localhost.localdomain")
		sans.Email = append(sans.Email, "root@localhost", "root@example.com")
		sans.IPs = append(sans.IPs, ips...)
	}

	app.Logger.Debug("Building certificate request for webservice",
		"webservice", wsName,
		"cn", keyAttrs.CN,
		"sans_dns", sans.DNS,
		"use_local_ca", useLocalCA)

	// Use ACME only when the webservice itself explicitly declares ACME via
	// certificate.acme.challenge. This matches the reference implementation:
	// internal/trusted webservices are issued by the local CA (whose root is
	// cross-signed during platform init), and only webservices that opt in
	// to a public ACME directory — typically the internet-facing public
	// webservice with its own public FQDN — go through ACME (http-01 /
	// dns-01). Node identity (EK / IDevID / IAK) is obtained separately
	// during ProvisionPlatform via endorse-01 / enroll-01 — not through this
	// webservice-cert path.
	wantsACME := wsConfig.Certificate.ACME != nil &&
		wsConfig.Certificate.ACME.Challenge != ""
	if wantsACME && app.ACMEConfig != nil && app.ACMEConfig.Client != nil &&
		app.ACMEConfig.Client.DirectoryURL != "" && !useLocalCA {

		challengeType := wsConfig.Certificate.ACME.Challenge
		authzType := wsConfig.Certificate.ACME.AuthzType
		if authzType == "" {
			authzType = "dns"
		}
		authzValue := wsConfig.Certificate.ACME.AuthzValue
		if authzValue == "" {
			authzValue = keyAttrs.CN
		}

		app.Logger.Info("Requesting TLS certificate via ACME client",
			"webservice", wsName,
			"cn", keyAttrs.CN,
			"directory", app.ACMEConfig.Client.DirectoryURL,
			"challenge_type", challengeType,
			"authz_type", authzType)

		if app.ACMEClient == nil {
			// Try ACME client init — the CA bundle is typically already in the OS
			// trust store (installed by ISO installer or platform-initrd). Fall
			// back to BootstrapTrust only on TLS failure.
			if err := app.InitACMEClient(ctx, true); err != nil {
				app.Logger.Warn("ACME client init failed, attempting trust bootstrap",
					"webservice", wsName, "error", err)
				if bsErr := app.BootstrapTrust(ctx); bsErr != nil {
					app.Logger.Error(bsErr, "Trust bootstrap also failed", "webservice", wsName)
					return &CommandOutputError{Msg: fmt.Sprintf("failed to initialize ACME client for webservice %s", wsName), Err: err, Detail: fmt.Sprintf(" (bootstrap: %v)", bsErr)}
				}
				if err := app.InitACMEClient(ctx, true); err != nil {
					app.Logger.Error(err, "ACME client init failed after trust bootstrap", "webservice", wsName)
					return &WrappedError{Msg: fmt.Sprintf("failed to initialize ACME client for webservice %s after bootstrap", wsName), Err: err}
				}
			}
		}

		csrDER, err := app.CA.CreateCSR(ctx, &quicbaasca.CACertificateRequest{
			KeyAttributes: keyAttrs,
			Valid:         365,
			Subject: quicbaasca.CASubject{
				CommonName:   keyAttrs.CN,
				Organization: wsConfig.Certificate.Subject.Organization,
				Country:      wsConfig.Certificate.Subject.Country,
				Province:     wsConfig.Certificate.Subject.Province,
				Locality:     wsConfig.Certificate.Subject.Locality,
				Address:      wsConfig.Certificate.Subject.Address,
				PostalCode:   wsConfig.Certificate.Subject.PostalCode,
			},
			SANS: sans,
		})
		if err != nil {
			app.Logger.Error(err, "Failed to create CSR for ACME", "webservice", wsName, "cn", keyAttrs.CN)
			return &WrappedError{Msg: fmt.Sprintf("failed to create CSR for ACME webservice %s", wsName), Err: err}
		}

		acmeCertRequest := &trustedca.ACMECertificateRequest{
			AuthzType:     authzType,
			AuthzValue:    authzValue,
			ChallengeType: challengeType,
			CSR:           csrDER,
		}
		cert, err := app.ACMEClient.RequestCertificate(ctx, acmeCertRequest)
		if err != nil {
			app.Logger.Error(err, "Failed to request certificate via ACME",
				"webservice", wsName, "cn", keyAttrs.CN, "challenge_type", challengeType)
			return &WrappedError{Msg: fmt.Sprintf("failed to request ACME certificate for webservice %s", wsName), Err: err}
		}
		certDER = cert.Raw

		app.Logger.Info("TLS certificate obtained via ACME",
			"webservice", wsName, "cn", keyAttrs.CN, "serial", cert.SerialNumber.String())

	} else {
		// Issue from local CA
		app.Logger.Info("Issuing TLS certificate from local CA", "webservice", wsName, "cn", keyAttrs.CN)

		certReq := &quicbaasca.CACertificateRequest{
			Subject: quicbaasca.CASubject{
				CommonName:   keyAttrs.CN,
				Organization: wsConfig.Certificate.Subject.Organization,
				Country:      wsConfig.Certificate.Subject.Country,
				Province:     wsConfig.Certificate.Subject.Province,
				Locality:     wsConfig.Certificate.Subject.Locality,
				Address:      wsConfig.Certificate.Subject.Address,
				PostalCode:   wsConfig.Certificate.Subject.PostalCode,
			},
			SANS:          sans,
			Valid:         365,
			KeyAttributes: keyAttrs,
		}

		localCert, err := app.CA.IssueCertificate(ctx, certReq)
		if err != nil {
			app.Logger.Error(err, "Failed to issue TLS certificate from local CA", "webservice", wsName, "cn", keyAttrs.CN)
			return &WrappedError{Msg: fmt.Sprintf("failed to issue certificate for webservice %s", wsName), Err: err}
		}
		certDER = localCert.Certificate.Raw

		app.Logger.Info("TLS certificate issued successfully from local CA",
			"webservice", wsName, "cn", keyAttrs.CN, "serial", localCert.SerialNumber.String())

		// Cross-sign if configured.
		//
		// Failures here are non-fatal: the webservice already has a
		// locally-issued (internal trust chain) cert and can serve traffic.
		// Cross-signing attaches a SECOND chain rooted in a public ACME
		// directory (Let's Encrypt-class) so browsers accept the TLS
		// handshake on the open internet, but until the node's public
		// network path + public DNS are operational the cross-signer ACME
		// server can't reach the http-01 challenge responder. Log WARN,
		// keep serving the internal cert, and let the scheduled cert
		// renewal handler retry cross-signing on a later cycle once the
		// network becomes public-reachable.
		if wsConfig.Certificate.ACME != nil && wsConfig.Certificate.ACME.CrossSign != nil {
			app.Logger.Info("Cross-signing TLS certificate",
				"webservice", wsName, "cn", keyAttrs.CN,
				"cross_signer", wsConfig.Certificate.ACME.CrossSign.DirectoryURL)

			csrDER, err := app.CA.CreateCSR(ctx, certReq)
			if err != nil {
				app.Logger.Warn("cross-sign skipped — CSR creation failed (non-fatal)",
					"webservice", wsName, "cn", keyAttrs.CN, "err", err.Error())
			} else if crossSigner, err := app.NewACMECrossSigner(wsConfig.Certificate.ACME.CrossSign, true); err != nil {
				app.Logger.Warn("cross-sign skipped — ACME cross-signer init failed (non-fatal)",
					"webservice", wsName, "cn", keyAttrs.CN, "err", err.Error())
			} else if xsignedCert, err := crossSigner.CrossSign(ctx, csrDER, localCert.Certificate.Raw); err != nil {
				app.Logger.Warn("cross-sign skipped — public ACME cross-sign failed (non-fatal; will retry at renewal)",
					"webservice", wsName, "cn", keyAttrs.CN, "err", err.Error())
			} else {
				xsignedDER = xsignedCert.Raw
				app.Logger.Info("TLS certificate cross-signed successfully", "webservice", wsName, "cn", keyAttrs.CN)
			}
		}
	}

	if app.DebugFlag {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return &WrappedError{Msg: "failed to parse TLS certificate", Err: err}
		}
		fmt.Printf("Web Server TLS Certificate (%s):\n", wsName)
		fmt.Println(xkmssdk.CertToString(cert))

		if xsignedDER != nil {
			xsignedCert, err := x509.ParseCertificate(xsignedDER)
			if err != nil {
				return &WrappedError{Msg: "failed to parse cross-signed certificate", Err: err}
			}
			issuerCN, err := util.ParseFQDN(wsConfig.Certificate.ACME.CrossSign.DirectoryURL)
			if err != nil {
				app.Logger.Error(err, "Failed to parse cross-signer directory URL",
					"webservice", wsName, "url", wsConfig.Certificate.ACME.CrossSign.DirectoryURL)
				return &WrappedError{Msg: fmt.Sprintf("failed to parse cross-signer directory URL for webservice %s", wsName), Err: err}
			}
			fmt.Printf("Cross-Signed (%s) TLS Certificate:\n", issuerCN)
			fmt.Println(xkmssdk.CertToString(xsignedCert))
		}
	}

	// Publish DANE TLSA records for the webservice certificate
	if err := app.publishDANETLSA(wsName, certDER, keyAttrs); err != nil {
		app.Logger.Warn("failed to publish DANE TLSA records",
			"webservice", wsName, "error", err)
		// Non-fatal: webservice can still operate without DANE records
	}

	// Register this webservice as a cert target so the platform
	// cert-renewal scheduler handler (pkg/app/cert_renewal_handler.go)
	// picks it up alongside BMC targets. Replace (not Register)
	// because re-issuance on renewal re-enters this function and we
	// want the update to be idempotent.
	if target, err := buildWebServiceCertTarget(ctx, wsName, wsConfig, keyAttrs, certDER, app); err != nil {
		app.Logger.Warn("failed to build webservice cert target",
			"webservice", wsName, "error", err)
		// Non-fatal: cert is issued and installed; renewal won't
		// happen automatically but manual reissue works.
	} else if err := app.certTargets().Replace(target); err != nil {
		app.Logger.Warn("failed to register webservice cert target",
			"webservice", wsName, "error", err)
	}

	return nil
}

// certTargets returns the platform's CertTargetRegistry, lazily
// constructing it on first access. Thread-safe for the common
// single-goroutine boot-time init pattern; callers that mutate from
// multiple goroutines must coordinate.
func (app *App) certTargets() *CertTargetRegistry {
	if app.CertTargets == nil {
		app.CertTargets = NewCertTargetRegistry()
	}
	return app.CertTargets
}

// buildWebServiceCertTarget constructs a CertTarget for a webservice
// TLS identity. The Current closure performs a live TLS handshake
// against the local webservice endpoint so the renewal handler always
// sees the certificate actually being served, not a stale cached copy.
// The Reissue closure re-invokes issueWebServiceCertificate, which
// loops back through here to update the target in place via Replace.
func buildWebServiceCertTarget(ctx context.Context, wsName string, wsConfig *v1.Config, keyAttrs *xkmssdk.KeyAttributes, certDER []byte, app *App) (*CertTarget, error) {
	// Build a trusted root pool from the platform CA so the live
	// handshake validates the served certificate without
	// InsecureSkipVerify.
	rootCert, err := app.CA.TrustedRoot()
	if err != nil {
		return nil, ErrWebserviceCertRead{Cause: &WrappedError{Msg: "trusted root", Err: err}}
	}
	caPool, err := app.CA.TrustedRootCertPool(rootCert)
	if err != nil {
		return nil, ErrWebserviceCertRead{Cause: &WrappedError{Msg: "cert pool", Err: err}}
	}

	port := wsConfig.TLSPort
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	return &CertTarget{
		Name: "webservice." + wsName,
		Kind: CertKindWebservice,
		Current: func(ctx context.Context) (*x509.Certificate, error) {
			conn, dialErr := tls.DialWithDialer(
				&net.Dialer{Timeout: 5 * time.Second},
				"tcp",
				addr,
				&tls.Config{
					RootCAs: caPool,
				},
			)
			if dialErr != nil {
				return nil, ErrWebserviceCertRead{Cause: dialErr}
			}
			defer conn.Close()
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				return nil, ErrWebserviceCertRead{
					Cause: errors.New("no peer certificates"),
				}
			}
			return certs[0], nil
		},
		Reissue: func(reissueCtx context.Context) error {
			return app.issueWebServiceCertificate(reissueCtx, wsName, wsConfig, keyAttrs)
		},
	}, nil
}

// publishDANETLSA publishes DANE TLSA records for a webservice TLS certificate.
// It publishes DANE-TA (Usage=2) from the CA certificate and optionally DANE-EE
// (Usage=3) from the leaf certificate if configured. Publication failure is
// non-fatal; callers should log and continue.
func (app *App) publishDANETLSA(wsName string, certDER []byte, keyAttrs *xkmssdk.KeyAttributes) error {
	if app.DNSConfig == nil || app.DNSConfig.DANE == nil || !app.DNSConfig.DANE.Enabled {
		return nil
	}
	if !app.DNSConfig.DANE.AutoGenerate {
		return nil
	}
	// Ensure the service registry (and DNS service) are initialized.
	// The service registry uses lazy initialization, so the DNS service
	// may not be created yet when webservice certs are issued during startup.
	if app.DNSService == nil {
		app.ServiceRegistry()
	}
	if app.DNSService == nil {
		app.Logger.Debug("DNS service not available, skipping DANE TLSA publication",
			"webservice", wsName)
		return nil
	}

	// Reuse the single DANE publisher instance (shared with the
	// SDK-registered publisher) so there is one DNS-write path.
	app.ensureDANEPublisher()

	// Parse the leaf certificate from DER
	leafCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return &ErrDANECertParse{Cause: err}
	}

	// Get the CA certificate for DANE-TA record.
	// Prefer intermediate CA; fall back to root CA.
	var caCert *x509.Certificate
	caCert, err = app.CA.TrustedIntermediate()
	if err != nil || caCert == nil {
		caCert, err = app.CA.TrustedRoot()
		if err != nil {
			return &ErrDANEPublish{
				Hostname: leafCert.Subject.CommonName,
				Cause:    err,
			}
		}
	}

	// Determine the hostname from the certificate CN
	hostname := leafCert.Subject.CommonName

	// Determine the zone name by matching the hostname against known DNS zones
	zoneName, err := app.resolveDANEZone(hostname)
	if err != nil {
		return err
	}

	port := app.DNSConfig.DANE.DefaultPort
	if port == 0 {
		port = 443
	}

	ctx := context.Background()
	if err := app.danePublisher.PublishForCertificate(ctx, leafCert, caCert, hostname, port, zoneName); err != nil {
		return &ErrDANEPublish{
			Hostname: hostname,
			Cause:    err,
		}
	}

	app.Logger.Info("DANE TLSA records published",
		"webservice", wsName,
		"hostname", hostname,
		"zone", zoneName,
		"port", port)

	return nil
}

// resolveDANEZone determines the DNS zone name for a given hostname by checking
// the platform's configured internal and public DNS zones.
func (app *App) resolveDANEZone(hostname string) (string, error) {
	if app.DNSConfig == nil {
		return "", &ErrDANENoZone{Hostname: hostname}
	}

	// Normalize hostname to FQDN with trailing dot
	fqdn := hostname
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	// Check internal zone
	if app.DNSConfig.InternalServer != nil {
		zone := app.DNSConfig.InternalServer.Zone.Name
		if zone != "" && strings.HasSuffix(fqdn, "."+zone) {
			return zone, nil
		}
	}

	// Check public zone
	if app.DNSConfig.PublicServer != nil {
		zone := app.DNSConfig.PublicServer.Zone.Name
		if zone != "" && strings.HasSuffix(fqdn, "."+zone) {
			return zone, nil
		}
	}

	// Try to extract domain suffix from hostname
	// e.g., "server.example.com" -> "example.com."
	parts := strings.SplitN(fqdn, ".", 2)
	if len(parts) == 2 && parts[1] != "" {
		candidateZone := parts[1]
		// Verify the zone exists in the DNS service
		ctx := context.Background()
		if _, err := app.DNSService.Zone(ctx, candidateZone); err == nil {
			return candidateZone, nil
		}
	}

	return "", &ErrDANENoZone{Hostname: hostname}
}

// ensureDANEPublisher lazily constructs the single DNS-backed
// bootstrap.DANEPublisher and caches it on the app. It is shared by the
// platform's cert-deriving publication flow (publishDANETLSA / rollover) and
// the SDK-registered DANEPublisherAdapter so there is exactly one DNS-write
// path. Callers must ensure app.DNSService and app.DNSConfig.DANE are set.
func (app *App) ensureDANEPublisher() *bootstrap.DANEPublisher {
	if app.danePublisher == nil {
		app.danePublisher = bootstrap.NewDANEPublisher(app.DNSService, app.DNSConfig.DANE, app.Logger)
	}
	return app.danePublisher
}

// wireDANEPublisherBackend registers the platform DNS-backed DANE publisher
// with the embedded QuicBaaS server's lazy adapter so
// Security().Trust().PublishDANE writes pre-derived TLSA records through the
// platform DNS service. It is a no-op when DANE is disabled, when the storage
// factory is not an embedded QuicBaaS factory, or when the embedded server has
// no DANE adapter (remote transport modes).
func (app *App) wireDANEPublisherBackend() {
	if app.DNSConfig == nil || app.DNSConfig.DANE == nil || !app.DNSConfig.DANE.Enabled {
		return
	}
	if app.DNSService == nil {
		return
	}
	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok {
		return
	}
	adapter := dbFactory.DANEPublisher()
	if adapter == nil {
		return
	}
	adapter.SetBackend(func() (quicbaas.DANERecordWriter, quicbaas.DANEZoneResolver) {
		if app.DNSService == nil {
			return nil, nil
		}
		return app.ensureDANEPublisher(), app.resolveDANEZoneFromTLSA
	})
}

// resolveDANEZoneFromTLSA resolves the authoritative DNS zone that owns a TLSA
// record from its owner name (e.g. "_443._tcp.host.example.com."). It strips
// the RFC 6698 "_<port>._<proto>." prefix to recover the service hostname and
// delegates to resolveDANEZone for the actual zone match.
func (app *App) resolveDANEZoneFromTLSA(tlsaName string) (string, error) {
	hostname := strings.TrimSuffix(tlsaName, ".")
	// Strip leading "_port._proto." labels if present.
	for i := 0; i < 2; i++ {
		if !strings.HasPrefix(hostname, "_") {
			break
		}
		idx := strings.IndexByte(hostname, '.')
		if idx < 0 {
			break
		}
		hostname = hostname[idx+1:]
	}
	return app.resolveDANEZone(hostname)
}

// Returns a new platform XKMS backend given a "keystores" config,
// the key directory, security officer secret and user pin. An
// optional key backend may be provided to override the default
// storage location.
func (app *App) XKMSFromConfig(
	config *platform.XKMSConfig,
	keyDir string,
	soPIN xkmssdk.Password,
	userPIN xkmssdk.Password,
	backend xkmssdk.TPMKeyBackend) (*platform.XKMS, error) {

	if app.PlatformKS == nil {
		app.InitPlatformKeyStore(soPIN, userPIN)
	}

	if backend == nil {
		var err error
		backend, err = newKeyBackend(app.Logger, keyDir)
		if err != nil {
			return nil, err
		}
	}

	// Create storage backends for keys and certs using xkms native file storage
	keyStorage, err := xkmssdk.NewFileStorageBackend(keyDir)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create key storage", Err: err}
	}
	certStorage, err := xkmssdk.NewFileStorageBackend(keyDir)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create cert storage", Err: err}
	}

	kc, err := platform.NewXKMS(
		app.Logger.Slog(),
		config,
		backend,
		keyStorage,
		certStorage,
		app.TPM,
		app.PlatformKS)
	if err != nil {
		return nil, err
	}
	return kc, nil
}

// Creates a new x509 certificate store, with an optional object
// store backend to override the default storage location.
func (app *App) NewCertificateStore(
	objStore object.ObjectStorer) (localcertstore.CertificateStorer, error) {

	if objStore == nil {
		objStore = app.ObjectStore
	}
	if objStore == nil {
		return nil, ErrNilObjectStore{}
	}
	certStore, err := localcertstore.NewCertificateStore(
		app.Logger,
		objStore)
	if err != nil {
		return nil, err
	}
	return certStore, nil
}

// Initialize the platform log file
func (app *App) InitLogFile(uid, gid int) *os.File {
	// Same defensive fallback as initLogger — Name is ldflag-populated
	// and is empty on bare `go build` runs, which would produce a
	// hidden ".log" file.
	logName := Name
	if logName == "" {
		logName = "platformd"
	}
	logFile := fmt.Sprintf("%s/%s.log", app.LogDir, logName)
	if err := os.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	if uid == 0 {
		if err = os.Chown(logFile, uid, gid); err != nil {
			log.Fatal(err)
		}
		perm := os.FileMode(0644)
		if app.DebugFlag {
			perm = os.ModePerm
		}
		if err = os.Chmod(logFile, perm); err != nil {
			log.Fatal(err)
		}
	}
	return f
}

// If started as root, drop the privileges after startup to
// the lesser privileged app user.
func (app *App) DropPrivileges() {
	if runtime.GOOS != "linux" {
		return
	}
	if syscall.Getuid() == 0 && app.RuntimeUser != "root" {
		app.Logger.Debugf("Running as root, downgrading to user %s", app.RuntimeUser)
		user, err := user.Lookup(app.RuntimeUser)
		if err != nil {
			log.Fatalf("setuid %s user not found! Error: %s", app.RuntimeUser, err)
		}
		uid, err := strconv.ParseInt(user.Uid, 10, 32)
		if err != nil {
			app.Logger.Fatalf("Unable to parse UID: %s", err)
		}
		gid, err := strconv.ParseInt(user.Gid, 10, 32)
		if err != nil {
			app.Logger.Fatalf("Unable to parse GID: %s", err)
		}
		cerr := syscall.Setgid(int(gid))
		if cerr != nil {
			app.Logger.Fatalf("Unable to setgid: message=%s", cerr)
		}
		cerr = syscall.Setuid(int(uid))
		if cerr != nil {
			app.Logger.Fatalf("Unable to setuid: message=%s", cerr)
		}
		app.InitLogFile(int(uid), int(gid))
	}
}

func DefaultTestConfig() *App {
	// Storage is nil initially; tests must start the QuicBaaS factory
	// to get an ObjectStorage client, or inject one via TestConfigWithStorage.
	return TestConfigWithStorage(nil)
}

func TestConfigWithStorage(storage objectstorage.Client) *App {
	Name = "trusted-platform"

	app := NewApp()
	app.DebugFlag = true
	app.DebugSecretsFlag = true
	app.Storage = storage

	// Create a test-specific config with paths that don't require root
	testConfig := DefaultConfig
	testConfig.ConfigDir = "trusted-data/etc"
	testConfig.LogDir = "trusted-data/log"
	testConfig.PlatformDir = "trusted-data"

	configYaml, err := yaml.Marshal(testConfig)
	if err != nil {
		panic(err)
	}

	fmt.Println("Test configuration:")
	fmt.Println(string(configYaml))

	// Create log directory on real filesystem for tests
	if err := os.MkdirAll(testConfig.LogDir, os.ModePerm); err != nil {
		panic(err)
	}
	logFile := fmt.Sprintf("%s/trusted-platform.log", testConfig.LogDir)
	if err := os.WriteFile(logFile, []byte{}, os.ModePerm); err != nil {
		panic(err)
	}

	// Write app config to real filesystem for viper
	if err := os.MkdirAll(testConfig.ConfigDir, os.ModePerm); err != nil {
		panic(err)
	}
	configFile := fmt.Sprintf("%s/config.yaml", testConfig.ConfigDir)
	if err := os.WriteFile(configFile, configYaml, os.ModePerm); err != nil {
		panic(err)
	}

	// Configure viper with real filesystem
	viper.AddConfigPath(testConfig.ConfigDir)
	viper.SetConfigFile(configFile)

	// Debug info
	fmt.Println(viper.GetViper().ConfigFileUsed())
	if err = viper.ReadInConfig(); err != nil {
		panic(err)
	}

	// Unmarshal with TextUnmarshaler support for custom types
	if err := viper.Unmarshal(app, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.TextUnmarshallerHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	)); err != nil {
		panic(err)
	}

	app.Logger = logging.NewLoggerWithFormat(slog.LevelDebug, logging.FormatJSON, os.Stdout)

	return app
}

func parsePublicIPs(_ Environment) (net.IP, net.IP, error) {
	// Configure HTTP client with transport settings optimized for NAT environments
	transport := &http.Transport{
		// Disable HTTP keep-alive to avoid connection reuse issues through NAT
		DisableKeepAlives: true,
		// Ensure TCP connections are fresh for each request
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	ipv4Resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		return nil, nil, err
	}
	defer ipv4Resp.Body.Close()

	var ipv4Data struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(ipv4Resp.Body).Decode(&ipv4Data); err != nil {
		return nil, nil, err
	}
	ipv4 := net.ParseIP(ipv4Data.IP)

	ipv6Resp, err := client.Get("https://api64.ipify.org?format=json")
	if err != nil {
		return nil, nil, err
	}
	defer ipv6Resp.Body.Close()

	var ipv6Data struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(ipv6Resp.Body).Decode(&ipv6Data); err != nil {
		return nil, nil, err
	}
	ipv6 := net.ParseIP(ipv6Data.IP)

	return ipv4, ipv6, nil
}

// DNSResolverForService returns a net.Resolver using the service-level override
// if set, falling back to the platform-wide dns.resolver config, then to the
// system resolver. The serviceOverride parameter is the service-specific DNS
// server address in "ip:port" format (e.g., from acme.client.dns-server).
func (app *App) DNSResolverForService(serviceOverride string) *net.Resolver {
	// Priority 1: Service-level override
	if serviceOverride != "" {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", serviceOverride)
			},
		}
	}

	// Priority 2: Platform-wide dns.resolver
	if app.DNSConfig != nil && app.DNSConfig.Resolver != nil {
		if resolver := app.DNSConfig.Resolver.NetResolver(); resolver != nil {
			return resolver
		}
	}

	// Priority 3: System resolver (nil means use default)
	return nil
}

// PrimaryDNSServer returns the primary DNS server address in "ip:port" format.
// PrimaryDNSServer checks the service-level override first, then falls back to
// the platform-wide dns.resolver config. An empty string is returned when
// neither is configured.
func (app *App) PrimaryDNSServer(serviceOverride string) string {
	if serviceOverride != "" {
		return serviceOverride
	}
	if app.DNSConfig != nil && app.DNSConfig.Resolver != nil {
		return app.DNSConfig.Resolver.PrimaryServer()
	}
	return ""
}

const (
	// defaultSystemTrustCertPath is the default path for installing the CA bundle
	// to the system trust store on Debian/Alpine systems.
	defaultSystemTrustCertPath = "/usr/local/share/ca-certificates/trusted-platform-ca.crt"
)

// BootstrapTrust performs runtime trust bootstrap by fetching the server's CA
// certificate bundle through the platform trust resolver's default-class
// strategy chain. The bundle is installed to the system trust store if
// configured. This method is a no-op when the default class is unset or lists
// only the embedded strategy (trust comes from the ISO-embedded CA bundle).
// When the default class's DANE DNS server is empty, it is populated from the
// platform-wide dns.resolver config so that DANE lookups use the correct
// server. When any class lists the tofu strategy, a qrdb-backed TOFU pin
// store is required — ErrBootstrapTOFUNoSDK is returned when the QuicBaaS SDK
// client is unavailable.
func (app *App) BootstrapTrust(ctx context.Context) error {
	if app.TrustConfig == nil {
		app.Logger.Debug("No trust config, skipping trust bootstrap")
		return nil
	}

	scope := app.TrustConfig.Default
	if scope == nil {
		app.Logger.Debug("No default trust scope, skipping trust bootstrap")
		return nil
	}

	if len(scope.Strategies) == 1 && scope.Strategies[0] == trust.StrategyEmbedded {
		app.Logger.Debug("Trust strategy is embedded, skipping runtime trust fetch")
		return nil
	}

	// Populate the DANE DNS server from the platform-wide resolver when
	// not explicitly set.
	if scope.HasStrategy(trust.StrategyDANE) && (scope.DANE == nil || scope.DANE.DNSServer == "") {
		if server := app.PrimaryDNSServer(""); server != "" {
			app.Logger.Info("Trust bootstrap using platform DNS resolver", "server", server)
			if scope.DANE == nil {
				scope.DANE = &trust.DANEConfig{}
			}
			scope.DANE.DNSServer = server
		}
	}

	// If any class chain lists the tofu strategy, construct a
	// ParameterStore-backed pin store and wire a WARN-level confirm hook.
	// If tofu is needed but the SDK client is not yet available, return
	// ErrBootstrapTOFUNoSDK — the daemon must not silently skip the strategy.
	resolverOpts := app.buildTOFUResolverOpts()
	if resolverOpts == nil && trustConfigNeedsTOFU(app.TrustConfig) {
		return ErrBootstrapTOFUNoSDK{}
	}

	resolver, err := trust.NewResolver(app.TrustConfig, app.Logger, resolverOpts...)
	if err != nil {
		return ErrBootstrapClientInit{Cause: err}
	}
	app.trustResolver = resolver

	bundlePEM, err := resolver.CABundlePEM(ctx, trust.ClassDefault)
	if err != nil {
		return ErrBootstrapFetchBundle{Cause: err}
	}

	if len(bundlePEM) == 0 {
		app.Logger.Warn("Trust bootstrap returned empty CA bundle, skipping installation")
		return nil
	}

	if scope.InstallToSystemTrust {
		certPath := defaultSystemTrustCertPath
		if err := trust.InstallToSystemTrust(bundlePEM, certPath); err != nil {
			return ErrBootstrapInstallBundle{Path: certPath, Cause: err}
		}
		app.Logger.Infof("CA bundle installed to %s. Run 'update-ca-certificates' to update the system trust store.", certPath)
	}

	return nil
}

// trustConfigNeedsTOFU reports whether any class chain in cfg lists the tofu
// strategy. Returns false when cfg is nil.
func trustConfigNeedsTOFU(cfg *trust.Config) bool {
	if cfg == nil {
		return false
	}
	for _, class := range []trust.Class{trust.ClassDefault, trust.ClassBMC, trust.ClassInternal} {
		if s := cfg.Scope(class); s != nil && s.HasStrategy(trust.StrategyTOFU) {
			return true
		}
	}
	return false
}

// buildTOFUResolverOpts constructs the trust.Option slice needed when any
// class chain lists the tofu strategy. The options carry a
// ParameterStore-backed pin store (Raft-replicated when clustered) and a
// confirm hook that logs every first-use pin at WARN level so operators can
// audit first-contact events.
//
// Returns nil when tofu is not needed (caller should skip) or when the
// Factory or SDKClient is not yet available (caller should return
// ErrBootstrapTOFUNoSDK after calling trustConfigNeedsTOFU).
func (app *App) buildTOFUResolverOpts() []trust.Option {
	if !trustConfigNeedsTOFU(app.TrustConfig) {
		return nil
	}

	dbFactory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok || dbFactory == nil {
		return nil
	}

	sdkClient := dbFactory.SDKClient()
	if sdkClient == nil {
		return nil
	}

	pinStore, err := quicbaas.NewTOFUPinStore(sdkClient)
	if err != nil {
		app.Logger.Warn("Failed to create TOFU pin store; tofu strategy will be unavailable", "error", err)
		return nil
	}

	logger := app.Logger
	confirmFn := func(_ context.Context, pin *trust.TOFUPin) error {
		logger.Warn("TOFU: first-use pin captured — verify this host manually",
			"host", pin.Host,
			"port", pin.Port,
			"spki_sha256", pin.SPKISHA256,
			"cert_fingerprint", pin.CertFingerprint,
			"source", pin.Source,
		)
		return nil
	}

	return []trust.Option{
		trust.WithTOFUPinStore(pinStore),
		trust.WithTOFUConfirmFunc(confirmFn),
	}
}

// assertNoUnresolvedKMSURI returns a non-nil error if v still contains a
// raw kms:// URI. Used as a defensive check at security-sensitive boundaries
// (TPM hierarchy auth, CA init, BMC creds) so a stale or unresolved URI
// fails the service start with a clear message instead of reaching
// TPM2_HierarchyChangeAuth as a 48-byte literal password.
func assertNoUnresolvedKMSURI(fieldName, v string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(v), "kms://") {
		return &MessageError{Msg: fmt.Sprintf("refusing to start: %s still holds an unresolved kms:// URI "+
			"(%q) — bootstrap resolver must run to completion before any "+
			"security field is consumed", fieldName, v)}
	}
	return nil
}
