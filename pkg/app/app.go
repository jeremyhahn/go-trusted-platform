package app

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/argon2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	libtpm2 "github.com/google/go-tpm/tpm2"
	acmedao "github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao/afero"
	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

var (
	ErrMissingEKWithoutEnabledCA        = errors.New("trusted-platform: EK certificate not found and unable to generate because the certificate authority is not enabled")
	ErrInvalidLocalAttestationSignature = errors.New("trusted-platform: local attestation signature verification failed")
	warnSimulatorWithEKCertHandle       = errors.New("trusted-platform: TPM Simulator w/ EK certificate (> 1024 bytes) configured for NV RAM storage. Using certificate store instead.")
	certPartition                       = "x509"

	EnvDev     Environment = "dev"
	EnvPreProd Environment = "preprod"
	EnvProd    Environment = "prod"
	EnvTest    Environment = "test"

	DefaultConfig = App{
		DebugFlag:        true,
		DebugSecretsFlag: true,
		CAConfig:         &ca.DefaultConfig,
		ConfigDir:        "/etc/trusted-platform",
		DatastoreConfig: &datastore.Config{
			Backend:          datastore.BackendAferoMemory.String(),
			ConsistencyLevel: datastore.ConsistencyLevelLocal.String(),
			ReadBufferSize:   50,
			RootDir:          "trusted-data/datastore",
			Serializer:       serializer.SERIALIZER_YAML.String(),
		},
		LogDir:           "trusted-data/log",
		Logger:           logging.DefaultLogger(),
		PlatformDir:      "trusted-data",
		Random:           rand.Reader,
		TPMConfig:        tpm2.DefaultConfig,
		WebServiceConfig: &webservice.DefaultConfigECDSA,
	}
)

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
	default:
		// Return user-defined environment
		return Environment(env)
	}
}

type App struct {
	ACMEConfig          *acme.Config                `yaml:"acme" json:"acme" mapstructure:"acme"`
	ACMEClient          *acme.Client                `yaml:"-" json:"-" mapstructure:"-"`
	Argon2              argon2.Argon2Config         `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	AttestationConfig   config.Attestation          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	BlobStore           blob.BlobStorer             `yaml:"-" json:"-" mapstructure:"-"`
	CA                  ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig            *ca.Config                  `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	ConfigDir           string                      `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	DatastoreConfig     *datastore.Config           `yaml:"datastore" json:"datastore" mapstructure:"datastore"`
	DebugFlag           bool                        `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag    bool                        `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	DNSConfig           *dns.Config                 `yaml:"dns" json:"dns" mapstructure:"dns"`
	DNSService          *dns.Service                `yaml:"-" json:"-" mapstructure:"-"`
	Domain              string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Environment         Environment                 `yaml:"-" json:"-" mapstructure:"-"`
	FS                  afero.Fs                    `yaml:"-" json:"-" mapstructure:"-"`
	Hostname            string                      `yaml:"hostname" json:"hostname" mapstructure:"hostname"`
	Hostmaster          string                      `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	LogDir              string                      `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	Logger              *logging.Logger             `yaml:"-" json:"-" mapstructure:"-"`
	PlatformDir         string                      `yaml:"platform-dir" json:"platform_dir" mapstructure:"platform-dir"`
	PlatformKS          tpm2ks.PlatformKeyStorer    `yaml:"-" json:"-" mapstructure:"-"`
	PlatformCertStore   certstore.CertificateStorer `yaml:"-" json:"-" mapstructure:"-"`
	PublicIPv4          net.IP                      `yaml:"-" json:"-" mapstructure:"-"`
	PublicIPv6          net.IP                      `yaml:"-" json:"-" mapstructure:"-"`
	PrivateIPv4         net.IP                      `yaml:"-" json:"-" mapstructure:"-"`
	PrivateIPv6         net.IP                      `yaml:"-" json:"-" mapstructure:"-"`
	Random              io.Reader                   `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser         string                      `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	SignerStore         keystore.SignerStorer       `yaml:"-" json:"-" mapstructure:"-"`
	ShutdownChan        chan bool                   `yaml:"-" json:"-" mapstructure:"-"`
	TPM                 tpm2.TrustedPlatformModule  `yaml:"-" json:"-" mapstructure:"-"`
	TPMConfig           tpm2.Config                 `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	WebServiceConfig    *v1.Config                  `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	ServerKeyAttributes *keystore.KeyAttributes     `yaml:"-" json:"-" mapstructure:"-"`

	serviceRegistry *service.Registry `yaml:"-" json:"-" mapstructure:"-"`
}

type AppInitParams struct {
	CADir        string
	ConfigDir    string
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
func (app *App) Init(initParams *AppInitParams) (*App, error) {

	// Override config file with CLI options
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.DebugSecretsFlag = initParams.DebugSecrets
		app.PlatformDir = initParams.PlatformDir
		app.ConfigDir = initParams.ConfigDir
		app.LogDir = initParams.LogDir
		app.Environment = ParseEnvironment(initParams.Env)
	}

	// Set the Afero file system abstraction library
	if app.FS == nil {
		// TODO: dynamically load mem/fs based on config
		app.FS = afero.NewOsFs()
	}

	// Initialize the configuration based on environment
	if err := app.initConfig(initParams.Env); err != nil {
		return nil, err
	}

	// Initialize the logger
	app.initLogger()

	// Set the hostname
	if app.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			panic("Unable to get the local hostname")
		}
		app.Hostname = hostname
	}

	// Parse private and public IP addresses
	if err := app.parsePrivateAndPublicIPs(); err != nil {
		return nil, err
	}

	// Initialize the platform datastores
	if err := app.initStores(); err != nil {
		return nil, err
	}

	// Starts the embedded DNS server
	app.StartDNS()

	// Parse the Security Officer and User PINs
	soPIN, userPIN, err := app.ParsePINs(initParams.SOPin, initParams.Pin)
	if err != nil {
		return app, err
	}

	// Initialize the TPM / platform
	if initParams.Initialize {
		err := app.InitTPM(soPIN, userPIN, initParams)
		if err != nil {
			return nil, err
		}
		return app, nil
	}
	if err := app.OpenTPM(initParams.Initialize); err != nil {
		return app, err
	}

	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		return app, err
	}

	// Some commands require the platform not be fully initialized
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
		return err
	}
	app.PublicIPv4 = publicIPv4
	app.PublicIPv6 = publicPv6

	app.Logger.Debug("IP Addresses",
		slog.String("Private IPv4", app.PrivateIPv4.String()),
		slog.String("Private IPv6", app.PrivateIPv6.String()),
		slog.String("Public IPv4", app.PublicIPv4.String()),
		slog.String("Public IPv6", app.PublicIPv6.String()))

	return nil
}

// Returns a singleton instance of the platform service registry
func (app *App) ServiceRegistry() *service.Registry {

	if app.serviceRegistry != nil {
		return app.serviceRegistry
	}

	daoFactory, err := kvstore.New(
		app.Logger,
		app.DatastoreConfig,
	)
	if err != nil {
		app.Logger.FatalError(err)
	}

	deviceService, err := device.NewService(&device.Config{
		Datastore: app.DatastoreConfig,
	})
	if err != nil {
		app.Logger.FatalError(err)
	}

	var dnsService *dns.Service
	if app.DNSConfig != nil {
		dnsService, err = app.newDNSService()
		if err != nil {
			app.Logger.FatalError(err)
		}
	}

	registry, err := service.NewRegistry(app.Logger, deviceService, dnsService, daoFactory)
	if err != nil {
		app.Logger.FatalError(err)
	}

	app.serviceRegistry = registry

	return registry
}

// Creates a new DNS service
func (app *App) newDNSService() (*dns.Service, error) {

	app.DNSConfig.Logger = app.Logger
	app.DNSConfig.PrivateIPv4 = app.PrivateIPv4.String()
	app.DNSConfig.PrivateIPv6 = app.PrivateIPv6.String()
	app.DNSConfig.PublicIPv4 = app.PublicIPv4.String()
	app.DNSConfig.PublicIPv6 = app.PublicIPv6.String()

	dsParams, err := datastore.ParamsFromConfig[*entities.Zone](
		app.DNSConfig.Datastore, dns.DatastorePartition)
	if err != nil {
		return nil, err
	}

	storeType, err := datastore.ParseStoreType(
		app.DNSConfig.Datastore.Backend)
	if err != nil {
		return nil, err
	}

	params := &dns.Params{
		AppName:     Name,
		AppVersion:  Version,
		Config:      app.DNSConfig,
		PrivateIPv4: app.PrivateIPv4,
		PrivateIPv6: app.PrivateIPv6,
		PublicIPv4:  app.PublicIPv4,
		PublicIPv6:  app.PublicIPv6,
		Datastore:   dns.NewDatastore(dsParams, storeType),
	}

	return dns.NewService(params)
}

// Starts the embedded DNS server
func (app *App) StartDNS() {
	app.Logger.Debug("Starting DNS service")
	if app.DNSConfig != nil {
		app.DNSConfig.PrivateIPv4 = app.PrivateIPv4.String()
		app.DNSConfig.PrivateIPv6 = app.PrivateIPv6.String()
		app.DNSConfig.PublicIPv4 = app.PublicIPv4.String()
		app.DNSConfig.PublicIPv6 = app.PublicIPv6.String()
		dns.Run(Name, Version, app.Logger, app.DNSConfig)
	}
}

// Returns the platform publicly routable Fully Qualified Domain Name
func (app *App) FQDN() string {
	return fmt.Sprintf("%s.%s", app.Hostname, app.Domain)
}

// Initializes the Viper configuration library and unmarshals it
// into this App struct.
func (app *App) initConfig(env string) error {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(app.ConfigDir)
	viper.AddConfigPath(fmt.Sprintf("etc/config/%s", Name))
	viper.AddConfigPath(fmt.Sprintf("%s/etc", app.PlatformDir))
	viper.AddConfigPath(fmt.Sprintf("$HOME/.%s/", Name))
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

	if err := viper.Unmarshal(app); err != nil {
		return err
	}

	return nil
}

// Creates a new file and STDOUT logger. If the global DebugFlag is set,
// the logger is initialized in debug mode, executing all logger.Debug*
// statements.
func (app *App) initLogger() {
	// if app.DebugFlag {
	// 	app.Logger = logging.DefaultLogger()
	// } else {
	if err := app.FS.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		panic(err)
	}
	logfile := fmt.Sprintf("%s/%s.log", app.LogDir, Name)
	if err := app.FS.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		panic(err)
	}
	file, err := app.FS.Create(logfile)
	if err != nil {
		panic(err)
	}
	if app.DebugFlag {
		app.Logger = logging.NewLogger(slog.LevelDebug, file)
	} else {
		app.Logger = logging.NewLogger(slog.LevelError, file)
	}
	// }
	app.Logger.Info("platform configuration",
		slog.String("file", viper.ConfigFileUsed()),
		slog.String("config-dir", app.ConfigDir),
		slog.String("log-dir", app.LogDir))
}

// Initialize blob and signer stores
func (app *App) initStores() error {
	blobstore, err := blob.NewFSBlobStore(app.Logger, app.FS, app.PlatformDir, nil)
	if err != nil {
		return err
	}
	app.BlobStore = blobstore
	app.SignerStore = keystore.NewSignerStore(app.BlobStore)
	cs, err := app.NewCertificateStore(app.BlobStore)
	if err != nil {
		return err
	}
	app.PlatformCertStore = cs
	return nil
}

// Parses the Security Officer and User PINs and returns a key store
// password object for each. If the provided PINs are set to the default
// password, a new AES-256 32 byte key is generated as a password.
func (app *App) ParsePINs(soPIN, userPIN []byte) (keystore.Password, keystore.Password, error) {

	if !app.DebugFlag {
		if soPIN == nil {
			soPIN = prompt.SOPin()
		}
		if userPIN == nil {
			userPIN = prompt.Pin()
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Compare(soPIN, []byte(keystore.DEFAULT_PASSWORD)) == 0 {
		soPIN = aesgcm.NewAESGCM(rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debug(
				"generated new Security Officer PIN", slog.String("sopin", string(soPIN)))
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Compare(userPIN, []byte(keystore.DEFAULT_PASSWORD)) == 0 {
		userPIN = aesgcm.NewAESGCM(rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debug(
				"generated new User PIN", slog.String("pin", string(userPIN)))
		}
	}
	sopin := keystore.NewClearPassword(soPIN)
	userpin := keystore.NewClearPassword(userPIN)
	return sopin, userpin, nil
}

// Initializes the Trusted Platform Module and provisions the platform. If
// a Security Officer or User PIN is set to the default, new random 32
// byte cryptographic PIN will be generated. The random input source for
// entropy is the Golang runtime rand.Reader. Possibly in the future this
// will support a HSM TRNG.
func (app *App) InitTPM(soPIN, userPIN keystore.Password, initParams *AppInitParams) error {
	if err := app.OpenTPM(initParams.Initialize); err != nil {
		if err == tpm2.ErrNotInitialized {
			if _, err := app.ProvisionPlatform(soPIN, userPIN, initParams); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

// Opens a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. A TPM software simulator is used if enabled
// in the TPM section of the platform configuration file.
func (app *App) OpenTPM(initialize bool) error {
	if app.TPMConfig.EK == nil {
		return tpm2.ErrNotInitialized
	}
	path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
	backend := keystore.NewFileBackend(app.Logger, app.FS, path)
	if app.TPM == nil {
		var certStore certstore.CertificateStorer
		var err error
		tpmPartition := "blobs/tpm2"
		tpmBlobStore, err := blob.NewFSBlobStore(app.Logger, app.FS, app.PlatformDir, &tpmPartition)
		if err != nil {
			return err
		}
		if app.TPMConfig.EK.CertHandle == 0 {
			// Use the certificate store for the EK cert instead of NV RAM
			certStore, err = app.NewCertificateStore(tpmBlobStore)
			if err != nil {
				return err
			}
		}
		params := &tpm2.Params{
			Backend:      backend,
			BlobStore:    tpmBlobStore,
			CertStore:    certStore,
			Config:       &app.TPMConfig,
			DebugSecrets: app.DebugSecretsFlag,
			FQDN:         app.FQDN(),
			Logger:       app.Logger,
			SignerStore:  app.SignerStore,
		}
		var tpm tpm2.TrustedPlatformModule
		tpm, err = tpm2.NewTPM2(params)
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
		// Ensure the initialize flag is not set with an existing
		// EK provisioned in the TPM.
		if ekAttrs, err := tpm.EKAttributes(); err == nil && ekAttrs != nil {
			if initialize {
				return fmt.Errorf(
					"Initialize flag set while EK resident in TPM. "+
						" Clear the TPM if you wish to proceed with initilization (tpm2_clear -c p): %s",
					ekAttrs.CN)
			}
		}
	}
	return nil
}

// Returns the Platform key store. This is a TPM 2.0 key store used as
// a generic key and password store by the platform. The key store will
// be created and initialized if it doesn't already exist.
func (app *App) InitPlatformKeyStore(soPIN, userPIN keystore.Password) error {
	app.Logger.Info("Initializing platform (TPM 2.0) key store")
	if app.PlatformKS == nil {
		path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
		backend := keystore.NewFileBackend(app.Logger, app.FS, path)
		if app.TPMConfig.KeyStore.CN == "" {
			app.TPMConfig.KeyStore.CN = "platform"
		}
		tpmksParams := &tpm2ks.Params{
			Logger:       app.Logger,
			Backend:      backend,
			Config:       app.TPMConfig.KeyStore,
			DebugSecrets: app.DebugSecretsFlag,
			SignerStore:  app.SignerStore,
			TPM:          app.TPM,
		}
		ks, err := tpm2ks.NewKeyStore(tpmksParams)
		if err != nil {
			if err == keystore.ErrNotInitalized {
				if err := ks.Initialize(soPIN, userPIN); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		app.PlatformKS = ks
	}
	return nil
}

// Initializes a new ACME client using the account email provided in the
// platform configuration.
func (app *App) InitACMEClient(initialize bool) error {
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil {
		return nil
	}
	// if app.ACMEConfig.Server != nil {
	// 	if app.ACMEConfig.Server.DirectoryURL == app.ACMEConfig.Client.DirectoryURL {

	// 		// ACME client is configured to retrieve certificates from the ACME
	// 		// server running on this same instance of the platform software. Since
	// 		// the ACME client needs the server running before it can request a
	// 		// certificate and this is an initialize operation, the ACME client is
	// 		// only instantiated if there is a cross-signer configured for the
	// 		// web server's certificate.

	// 		if app.WebServiceConfig.Certificate.ACME != nil &&
	// 			app.WebServiceConfig.Certificate.ACME.CrossSigner != nil {

	// 			if app.WebServiceConfig.Certificate.ACME.CrossSigner.DirectoryURL == app.ACMEConfig.Client.DirectoryURL {
	// 				return acme.ErrCrossSignerSameDirectoryURL
	// 			}
	// 		}

	// 	}
	// }
	daoFactory, err := acmedao.NewFactory(
		app.Logger,
		app.DatastoreConfig,
	)
	if err != nil {
		return err
	}
	client, err := acme.NewClient(
		*app.ACMEConfig.Client,
		app.CA,
		daoFactory,
		app.DNSService,
		app.WebServiceConfig.Port,
		app.Logger,
		app.PlatformKS,
		app.TPM)
	if err != nil {
		return err
	}
	app.ACMEClient = client
	if initialize {
		if _, err := app.ACMEClient.RegisterAccount(); err != nil {
			return err
		}
	}
	if app.WebServiceConfig.Certificate.ACME != nil &&
		app.WebServiceConfig.Certificate.ACME.CrossSigner != nil &&
		app.ACMEConfig.Client.Account.Register {

		xsigner, err := app.ACMEClient.CrossSignerFromClient(
			app.WebServiceConfig.Certificate.ACME.CrossSigner)
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
func (app *App) NewACMECrossSigner(crossSigner acme.CrossSign, initialize bool) (*acme.Client, error) {
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil {
		return nil, nil
	}
	daoFactory, err := acmedao.NewFactory(
		app.Logger,
		app.DatastoreConfig,
	)
	if err != nil {
		return nil, err
	}
	client, err := acme.NewCrossSigner(
		acme.ClientConfig{
			ConsistencyLevel: app.ACMEConfig.Client.ConsistencyLevel,
			DirectoryURL:     crossSigner.DirectoryURL,
			Account:          app.ACMEConfig.Client.Account,
		},
		app.CA,
		daoFactory,
		app.DNSService,
		app.WebServiceConfig.Port,
		app.Logger,
		app.PlatformKS,
		app.TPM)
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
func (app *App) ProvisionPlatform(
	soPIN, userPIN keystore.Password,
	initParams *AppInitParams) (*keystore.KeyAttributes, error) {

	app.Logger.Debug("Provisioning TPM 2.0")

	// Provision the TPM
	if err := app.TPM.Provision(soPIN); err != nil {
		return nil, err
	}

	// Provision the platform TPM 2.0 key store
	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		return nil, err
	}

	// Initialize the Certificate Authorities
	if app.CAConfig != nil {
		if _, err := app.InitCA(soPIN, userPIN, initParams); err != nil {
			return nil, err
		}
	}

	// Initialize the ACME client if configured
	if app.ACMEClient == nil && app.ACMEConfig != nil {
		if app.ACMEConfig.Server != nil {
			if app.ACMEConfig.Server.DirectoryURL == app.ACMEConfig.Client.DirectoryURL {
				// Ignore errors here, as the ACME server needs to be bootstrapped
				// before the ACME client can request / renew certificates from the
				// ACME server running within the same instance of this platform software.
			}
		} else {
			if err := app.InitACMEClient(true); err != nil {
				return nil, err
			}
		}
	}

	// Imports the TPM Endorsement Key into the Certificate Authority
	ekCert, err := app.ImportEndorsementKeyCertificate()
	if err != nil {
		return nil, err
	}

	policyDigest := app.TPM.PlatformPolicyDigest()
	idevidAttrs, err := tpm2.IDevIDAttributesFromConfig(
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
				if err := app.InitACMEClient(initParams.Initialize); err != nil {
					return nil, err
				}
			}

			cert, err := app.ACMEClient.EnrollDevice(ca.CertificateRequest{
				Valid: app.CA.DefaultValidityPeriod(),
				Subject: ca.Subject{
					CommonName: idevidAttrs.CN,
				},
				PermanentID:   ekCert.SerialNumber.String(),
				ProdModel:     app.TPMConfig.IDevID.Model,
				ProdSerial:    app.TPMConfig.IDevID.Serial,
				KeyAttributes: idevidAttrs,
			})
			if err != nil {
				return nil, err
			}
			fmt.Println(certstore.ToString(cert))

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
			var tcgCSRIDevID *tpm2.TCG_CSR_IDEVID
			idevidAttrs, tcgCSRIDevID, err = app.TPM.CreateIDevID(iakAttrs, ekCert, nil)
			if err != nil {
				return nil, err
			}
			keystore.DebugKeyAttributes(app.Logger, idevidAttrs)

			// Verify the TCG_CSR_IDEVID and receive the encrypted challenge
			credentialBlob, encryptedSecret, secret, err := app.CA.VerifyTCG_CSR_IDevID(
				tcgCSRIDevID, iakAttrs.SignatureAlgorithm)
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
			if bytes.Compare(releasedCertInfo, secret) != 0 {
				return nil, tpm2.ErrInvalidActivationCredential
			}

			// Sign TCG_CSR_IDEVID, create IDevID x509 device certificate
			iakDER, idevidDER, err := app.CA.SignTCGCSRIDevID(tcgCSRIDevID, &ca.CertificateRequest{
				// KeyAttributes: ekAttrs,
				KeyAttributes: idevidAttrs,
				Valid:         0, // Valid until 99991231235959Z
				Subject: ca.Subject{
					CommonName:   idevidAttrs.CN,
					Organization: app.WebServiceConfig.Certificate.Subject.Organization,
					Country:      app.WebServiceConfig.Certificate.Subject.Country,
					Locality:     app.WebServiceConfig.Certificate.Subject.Locality,
					Address:      app.WebServiceConfig.Certificate.Subject.Address,
					PostalCode:   app.WebServiceConfig.Certificate.Subject.PostalCode,
				},
				SANS: &ca.SubjectAlternativeNames{
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
			if err := app.CA.ImportCertificate(iakCert); err != nil {
				return nil, err
			}

			// Import the IDevID certificate
			idevidCert, err := x509.ParseCertificate(idevidDER)
			if err != nil {
				return nil, err
			}
			if err := app.CA.ImportCertificate(idevidCert); err != nil {
				return nil, err
			}

			// Perform local TPM Quote - log errors but don't fail. Some embedded
			// systems don't support secure boot, or it may not be enabled.
			quote, nonce, err := app.AttestLocal(iakAttrs)
			if err != nil {
				app.Logger.Error(err)
			} else {
				// Verify the quote
				if err := app.VerifyLocalQuote(iakAttrs, quote, nonce); err != nil {
					app.Logger.Error(err)
				}
			}
		}
	}

	if err := app.InitWebServer(); err != nil {
		return nil, err
	}

	return idevidAttrs, nil
}

// Import TPM Endorsement Certificate - EK Credential Profile. Attempts
// to import the EK certificate from the TPM into the CA. If an EK
// certificate is not found, and the ek-gen options are set in the
// platform configuration file, a new EK certificate will be generated
// and imported into the TPM or certificate store. If the ACME client
// is configured, the EK certificate is requested from the Enterprise CA,
// otherwise, the EK certificate is generated using the local CA.
func (app *App) ImportEndorsementKeyCertificate() (*x509.Certificate, error) {

	if app.CAConfig == nil {
		return nil, ErrMissingEKWithoutEnabledCA
	}

	ekAttrs, err := app.TPM.EKAttributes()
	if err != nil {
		return nil, err
	}

	ekCert, err := app.TPM.EKCertificate()
	if err != nil {

		if err == tpm2.ErrEndorsementCertNotFound {

			var publicKey crypto.PublicKey

			if app.TPMConfig.EK.KeyAlgorithm == x509.RSA.String() {
				publicKey = app.TPM.EKRSA()
			} else if app.TPMConfig.EK.KeyAlgorithm == x509.ECDSA.String() {
				publicKey = app.TPM.EKECC()
			} else {
				app.Logger.Errorf(
					"unsupported TPM EK algorithm %s",
					app.TPMConfig.EK.KeyAlgorithm)
				return nil, keystore.ErrInvalidKeyAlgorithm

			}

			certReq := ca.CertificateRequest{
				KeyAttributes: ekAttrs,
				Subject: ca.Subject{
					CommonName:   ekAttrs.CN,
					Organization: app.WebServiceConfig.Certificate.Subject.Organization,
					Country:      app.WebServiceConfig.Certificate.Subject.Country,
					Locality:     app.WebServiceConfig.Certificate.Subject.Locality,
					Address:      app.WebServiceConfig.Certificate.Subject.Address,
					PostalCode:   app.WebServiceConfig.Certificate.Subject.PostalCode,
				},
				SANS: &ca.SubjectAlternativeNames{
					DNS: []string{
						app.Domain,
					},
					IPs: []string{},
					Email: []string{
						app.Hostmaster,
					},
				},
			}

			if app.ACMEClient != nil && app.ACMEConfig.Client.Enrollment != nil {
				// Request the EK certificate from the Enterprise CA if the ACME client
				// is configured with an enrollment challenge
				ekCert, err = app.ACMEClient.RequestEndorsementKeyCertificate(certReq)
				if err != nil {
					return nil, err
				}
			} else {
				// Generate new Endorsement Key x509 Certificate using the local CA
				ekCert, err = app.CA.IssueEKCertificate(certReq, publicKey)
				if err != nil {
					return nil, err
				}
			}
			fmt.Println(certstore.ToString(ekCert))

			// Write the EK cert to TPM NV RAM
			hierarchyAuth, err := ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
			if err != nil {
				return nil, err
			}

			if err := app.TPM.ProvisionEKCert(
				hierarchyAuth, ekCert.Raw); err != nil {

				// NOTE: TPM simulator throws an error here for certs
				// greater than 1024 bytes. To work around this, a warning
				// is emitted and the cert-handle attribute is ignored so
				// the certificate can be imported to the certificate store
				// instead of TPM NV RAM.
				if len(ekCert.Raw) > 1024 && app.TPMConfig.UseSimulator {
					if app.TPMConfig.EK.CertHandle > 0 {
						app.Logger.MaybeError(warnSimulatorWithEKCertHandle)
					}
				} else {
					app.Logger.Error(err)
				}
			}
			return ekCert, nil

		} else {
			return nil, err
		}
	}
	err = app.CA.ImportEndorsementKeyCertificate(ekAttrs, ekCert.Raw)
	if err != nil {
		return nil, err
	}

	return ekCert, nil
}

// Loads an initialized Certificate Authority
func (app *App) LoadCA(soPIN, userPIN keystore.Password) error {

	params := &ca.CAParams{
		Debug:        app.DebugFlag,
		DebugSecrets: app.DebugSecretsFlag,
		Logger:       app.Logger,
		Config:       *app.CAConfig,
		Fs:           app.FS,
		SelectedCA:   app.CAConfig.PlatformCA,
		Random:       app.Random,
		BlobStore:    app.BlobStore,
		SignerStore:  app.SignerStore,
		TPM:          app.TPM,
	}
	params.Identity = app.CAConfig.Identity[app.CAConfig.PlatformCA]

	caRoot := ca.HomeDirectory(app.FS, app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, app.FS, caRoot, &certPartition)
	if err != nil {
		return err
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		return err
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyringConfig.CN = params.Identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	backend := keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create keychain for the CA
	keychain, err := app.KeyringFromConfig(
		params.Identity.KeyringConfig,
		app.FS,
		caRoot,
		soPIN,
		userPIN,
		backend)
	if err != nil {
		return err
	}
	params.Keyring = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	if app.CAConfig.PlatformCA == 0 {

		parentCA, err := ca.NewParentCA(params)
		if err != nil {
			return err
		} else {
			app.CA = parentCA
		}
	} else {
		params.Identity = app.CAConfig.Identity[app.CAConfig.PlatformCA]
		intermediateCA, err := ca.NewIntermediateCA(params)
		if err != nil {
			return err
		}
		if err := intermediateCA.Load(); err != nil {
			return err
		}
		app.CA = intermediateCA
	}
	return nil
}

// Initializes all Certificate Authorities provided in the
// platform configuration file and returns the selected
// "Platform CA" as the default CA used for Platform operations.
func (app *App) InitCA(soPIN, userPIN keystore.Password, initParams *AppInitParams) (ca.CertificateAuthority, error) {

	if app.TPM == nil {
		if err := app.OpenTPM(initParams.Initialize); err != nil {
			return nil, err
		}
	}

	var platformCA ca.CertificateAuthority

	if len(app.CAConfig.Identity) == 0 {
		return nil, ca.ErrInvalidConfig
	}

	params := &ca.CAParams{
		Debug:        app.DebugFlag,
		DebugSecrets: app.DebugSecretsFlag,
		Logger:       app.Logger,
		Config:       *app.CAConfig,
		Fs:           app.FS,
		SelectedCA:   initParams.PlatformCA,
		Random:       app.Random,
		BlobStore:    app.BlobStore,
		SignerStore:  app.SignerStore,
		TPM:          app.TPM,
	}

	rootCA, err := app.InitRootCA(params, soPIN, userPIN)
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(app.CAConfig.Identity); i++ {
		thisCA := app.CAConfig.Identity[i]
		intermediateCA, err := app.InitIntermediateCA(
			params, thisCA, rootCA, soPIN, userPIN)
		if err != nil {
			return nil, err
		}
		if i == app.CAConfig.PlatformCA || i == len(app.CAConfig.Identity)-1 {
			platformCA = intermediateCA
		}
	}

	app.CA = platformCA

	return platformCA, nil
}

// Initializes a Root / Parent Certificate Authority
func (app *App) InitRootCA(
	params *ca.CAParams,
	soPIN, userPIN keystore.Password) (ca.CertificateAuthority, error) {

	fmt.Println("Initializing Root / Parent Certificate Authority")

	params.Identity = app.CAConfig.Identity[0]

	caRoot := ca.HomeDirectory(app.FS, app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, app.FS, caRoot, &certPartition)
	if err != nil {
		return nil, err
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		return nil, err
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyringConfig.CN = params.Identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	keyBackend := keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create keychain for the Parent / Root CA
	keychain, err := app.KeyringFromConfig(
		params.Identity.KeyringConfig,
		app.FS,
		caRoot,
		soPIN,
		userPIN,
		keyBackend)
	if err != nil {
		return nil, err
	}
	params.Keyring = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	// Creates a new Parent / Root Certificate Authority
	rootCA, err := ca.NewParentCA(params)
	if err != nil {
		return nil, err
	}

	// Initialize the CA by creating new keys and certificates
	if err := rootCA.Init(nil); err != nil {
		return nil, err
	}

	// Set the Root CA as the platform CA if it's the only
	// one configured
	if len(app.CAConfig.Identity) == 1 {
		app.CA = rootCA
	}

	return rootCA, nil
}

// Initializes an Intermediate Certificate Authority
func (app *App) InitIntermediateCA(
	caParams *ca.CAParams,
	identity ca.Identity,
	parentCA ca.CertificateAuthority,
	soPIN, userPIN keystore.Password) (ca.CertificateAuthority, error) {

	fmt.Println("Initializing Intermediate Certificate Authority")

	params := *caParams
	params.Identity = identity

	caRoot := ca.HomeDirectory(app.FS, app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, app.FS, caRoot, &certPartition)
	if err != nil {
		return nil, err
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		return nil, err
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyringConfig.CN = identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	backend := keystore.NewFileBackend(params.Logger, app.FS, caRoot)

	// Create keychain for the Intermediate CA
	keychain, err := app.KeyringFromConfig(
		params.Identity.KeyringConfig,
		app.FS,
		caRoot,
		soPIN,
		userPIN,
		backend)
	if err != nil {
		return nil, err
	}
	params.Keyring = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	// Create the new Intermediate CA
	intermediateCA, err := ca.NewIntermediateCA(&params)
	if err != nil {
		return nil, err
	}

	// Initialize the CA by creating new keys and certificates, using
	// the parentCA to sign for this new intermediate
	if err := intermediateCA.Init(parentCA); err != nil {
		return nil, err
	}

	// Set the platform CA
	app.CA = intermediateCA

	return intermediateCA, nil
}

// Performs a local TPM 2.0 attestation
func (app *App) AttestLocal(serverAttrs *keystore.KeyAttributes) (tpm2.Quote, []byte, error) {
	fmt.Println("Performing local attestation")
	quote, nonce, err := app.TPM.PlatformQuote(serverAttrs)
	if err != nil {
		return tpm2.Quote{}, nil, err
	}
	return quote, nonce, nil
}

// Verifies a local TPM 2.0 quote
func (app *App) VerifyLocalQuote(
	akAttrs *keystore.KeyAttributes,
	quote tpm2.Quote,
	nonce []byte) error {

	err := app.CA.VerifyQuote(akAttrs, quote, nonce)
	if err != nil {
		// TODO: Re-seal the CA, run intrusion detection handlers,
		// wipe the file system, etc in an attempt to mitigate the
		// attack or unauthorized / unexpected changes.
		return ErrInvalidLocalAttestationSignature
	}

	if err := app.CA.ImportLocalAttestation(
		akAttrs, quote, app.PlatformKS.Backend()); err != nil {

		return err
	}

	return nil
}

// Starts the embedded web server. When the initialize parameter is true, the
// the web server's TLS certificate configuration is used to generate a new
// pre-configured TLS cert for the web server. If the common name matches the
// common name of the IDevID key attributes, then the IDevID key is used to generate
// the TLS certiicate, otherwise, a new key will be generated whose common name
// matches the common name configured in the web server's TLS certificate configuration.
// If an ACME client section has been provided in the platform configuration,
// the ACME directory specified in this block will be used to sign the generated CSR.
// If an ACME cross-sign configuration is also present in the certificate configuration,
// the ACME directory provided in the cross-signing configuration will be used to
// cross-sign the certificate.
func (app *App) InitWebServer() error {

	if app.WebServiceConfig == nil {
		app.Logger.Warn("web services disabled")
		return nil
	}

	app.Logger.Info("Initializing web services")

	if app.TPMConfig.IDevID != nil &&
		app.TPMConfig.IDevID.CN == app.WebServiceConfig.Certificate.Subject.CommonName {

		app.Logger.Info("using IDevID certificate for TLS")
		idevidAttrs, err := app.TPM.IDevIDAttributes()
		if err != nil {
			app.Logger.Error(err)
		}
		if app.TPMConfig.IDevID.Handle != 0 {
			idevidAttrs.TPMAttributes.HandleType = libtpm2.TPMHTPersistent
		}
		idevidAttrs.KeyType = keystore.KEY_TYPE_IDEVID
		app.ServerKeyAttributes = idevidAttrs
	} else {
		app.Logger.Info("using dedicated web server certificate for TLS")
		serverKeyAttrs, err := keystore.KeyAttributesFromConfig(app.WebServiceConfig.Key)
		if err != nil {
			return err
		}
		serverKeyAttrs.Parent = app.PlatformKS.SRKAttributes()
		serverKeyAttrs.CN = app.WebServiceConfig.Certificate.Subject.CommonName
		serverKeyAttrs.KeyType = keystore.KEY_TYPE_TLS
		serverKeyAttrs.TPMAttributes = &keystore.TPMAttributes{}
		app.ServerKeyAttributes = serverKeyAttrs
	}
	keystore.DebugKeyAttributes(app.Logger, app.ServerKeyAttributes)

	// Try to load the web services TLS cert
	pem, err := app.CA.PEM(app.ServerKeyAttributes)
	if err != nil {
		if err == certstore.ErrCertNotFound {

			// No cert, issue a platform server certificate for TLS encrypted web services
			certReq := ca.CertificateRequest{
				KeyAttributes: app.ServerKeyAttributes,
				Valid:         365, // days
				Subject: ca.Subject{
					// CommonName:   app.WebServiceConfig.Certificate.Subject.CommonName,
					CommonName:   app.ServerKeyAttributes.CN,
					Organization: app.WebServiceConfig.Certificate.Subject.Organization,
					Country:      app.WebServiceConfig.Certificate.Subject.Country,
					Province:     app.WebServiceConfig.Certificate.Subject.Province,
					Locality:     app.WebServiceConfig.Certificate.Subject.Locality,
					Address:      app.WebServiceConfig.Certificate.Subject.Address,
					PostalCode:   app.WebServiceConfig.Certificate.Subject.PostalCode,
				},
				SANS: &ca.SubjectAlternativeNames{
					DNS: []string{
						app.Domain,
					},
					IPs: []string{},
					Email: []string{
						app.Hostmaster,
					},
				},
			}

			// Include localhost SANS DNS, IPs, and and root email if config
			// is set to sans-include-localhost: true.
			if app.CAConfig.IncludeLocalhostSANS {
				// Parse list of usable local IPs
				ips, err := util.LocalAddresses()
				if err != nil {
					return err
				}
				certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost")
				certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost.localdomain")
				certReq.SANS.DNS = append(certReq.SANS.DNS, "localhost.localdomain")
				certReq.SANS.Email = append(certReq.SANS.Email, "root@localhost")
				certReq.SANS.Email = append(certReq.SANS.Email, "root@example.com")
				certReq.SANS.IPs = append(certReq.SANS.IPs, ips...)
			}

			// if app.ACMEClient == nil && app.ACMEConfig != nil {
			// 	if err := app.InitACMEClient(true); err != nil {
			// 		app.Logger.Error(err)
			// 		return nil
			// 	}
			// }

			// If the ACME client and server have the same diretory URL, that means this
			// is either a standalone server using self-signed certificates or the
			// first CA for an Enterprise / Privacy CA. Since the ACME server needs to
			// have a certificate before the client is able to connect to request one,
			// the ACME client is not used to bootstrap the node, but rather issue the
			// certificate directly from the local CA and then use ACME to renew the
			// certificate going forward.

			var certDER, xsignedDER []byte
			// if app.ACMEClient != nil {
			if app.ACMEConfig != nil && app.ACMEConfig.Client != nil &&
				(app.ACMEConfig.Server == nil || app.ACMEConfig.Server.DirectoryURL != app.ACMEConfig.Client.DirectoryURL) {

				if app.ACMEClient == nil && app.ACMEConfig != nil {
					if err := app.InitACMEClient(true); err != nil {
						app.Logger.Error(err)
						return nil
					}
				}

				acmeCertRequest := acme.CertificateRequest{
					ChallengeType: app.WebServiceConfig.Certificate.ACME.ChallengeType,
					CrossSigner:   app.WebServiceConfig.Certificate.ACME.CrossSigner,
					KeyAttributes: app.ServerKeyAttributes,
					Valid:         365, // days
					Subject: ca.Subject{
						// CommonName:   app.WebServiceConfig.Certificate.Subject.CommonName,
						CommonName:   app.ServerKeyAttributes.CN,
						Organization: app.WebServiceConfig.Certificate.Subject.Organization,
						Country:      app.WebServiceConfig.Certificate.Subject.Country,
						Province:     app.WebServiceConfig.Certificate.Subject.Province,
						Locality:     app.WebServiceConfig.Certificate.Subject.Locality,
						Address:      app.WebServiceConfig.Certificate.Subject.Address,
						PostalCode:   app.WebServiceConfig.Certificate.Subject.PostalCode,
					},
					SANS: &ca.SubjectAlternativeNames{
						DNS: []string{
							app.ServerKeyAttributes.CN,
						},
						IPs: []string{},
						Email: []string{
							app.Hostmaster,
						},
					},
				}
				// Request the web server certificate from the Enterprise / Privacy CA
				cert, _, err := app.ACMEClient.RequestCertificate(acmeCertRequest, true)
				if err != nil {
					return err
				}
				certDER = cert.Raw

			} else {

				// // Issue the web server certificate from the local CA
				// der, err = app.CA.IssueCertificate(certReq)
				// if err != nil {
				// 	return err
				// }

				_, err := app.CA.Keyring().GenerateKey(app.ServerKeyAttributes)
				if err != nil {
					return err
				}

				subject := ca.Subject{
					// CommonName:   app.WebServiceConfig.Certificate.Subject.CommonName,
					CommonName:   app.ServerKeyAttributes.CN,
					Organization: app.WebServiceConfig.Certificate.Subject.Organization,
					Country:      app.WebServiceConfig.Certificate.Subject.Country,
					Province:     app.WebServiceConfig.Certificate.Subject.Province,
					Locality:     app.WebServiceConfig.Certificate.Subject.Locality,
					Address:      app.WebServiceConfig.Certificate.Subject.Address,
					PostalCode:   app.WebServiceConfig.Certificate.Subject.PostalCode,
				}

				certReq := ca.CertificateRequest{
					Subject: subject,
					SANS: &ca.SubjectAlternativeNames{
						DNS: []string{
							app.ServerKeyAttributes.CN,
						},
						IPs: []string{},
						Email: []string{
							app.Hostmaster,
						},
					},
					Valid:         365, // days
					KeyAttributes: app.ServerKeyAttributes,
				}

				// Create locally generated and issued CSR and certificate for
				// the web server
				csrDER, err := app.CA.CreateCSR(certReq)
				if err != nil {
					return fmt.Errorf("failed to create CSR: %v", err)
				}
				csrPEM, err := ca.EncodeCSR(csrDER)
				if err != nil {
					return err
				}
				localCert, err := app.CA.SignCSR(csrPEM, &certReq)
				if err != nil {
					return err
				}
				if err := app.CA.ImportCertificate(localCert); err != nil {
					return err
				}
				certDER = localCert.Raw

				// Cross-sign the certificate if configured
				if app.WebServiceConfig.Certificate.ACME != nil &&
					app.WebServiceConfig.Certificate.ACME.CrossSigner != nil {

					authzType, err := acme.ParseAuthzIDFromChallengeType(
						app.WebServiceConfig.Certificate.ACME.ChallengeType)
					if err != nil {
						return err
					}
					acmeCertRequest := acme.CertificateRequest{
						ChallengeType: app.WebServiceConfig.Certificate.ACME.ChallengeType,
						CrossSigner:   app.WebServiceConfig.Certificate.ACME.CrossSigner,
						KeyAttributes: app.ServerKeyAttributes,
						Subject:       certReq.Subject,
						SANS:          certReq.SANS,
						AuthzID: &acme.AuthzID{
							Type:  &authzType.Type,
							Value: &subject.CommonName,
						},
					}
					crossSigner, err := app.NewACMECrossSigner(*app.WebServiceConfig.Certificate.ACME.CrossSigner, true)
					if err != nil {
						return err
					}
					xsignedCert, err := crossSigner.CrossSign(csrDER, localCert.Raw, acmeCertRequest)
					if err != nil {
						return err
					}
					xsignedDER = xsignedCert.Raw
				}

			}

			if app.DebugFlag {
				pem, err = certstore.EncodePEM(certDER)
				if err != nil {
					return err
				}
				fmt.Println("Web Server TLS certificate (PEM)")
				fmt.Println(string(pem))

				if xsignedDER != nil {
					xsignedPEM, err := certstore.EncodePEM(xsignedDER)
					if err != nil {
						return err
					}
					xsignedCert, err := x509.ParseCertificate(xsignedDER)
					if err != nil {
						return err
					}
					issuerCN, err := certstore.ParseIssuerCN(xsignedCert)
					if err != nil {
						return err
					}
					fmt.Printf("Cross-Signed (%s) TLS certificate (PEM)\n", issuerCN)
					fmt.Println(string(xsignedPEM))
				}
			}

		} else {
			return err
		}

	} else {

		// Loaded an already initialized web server

		if app.ServerKeyAttributes.PlatformPolicy {

			// Replace any password that might be defined in the platform configuration
			// with the PlatformPassword that retrieves the password from the TPM.
			app.ServerKeyAttributes.Password = tpm2.NewPlatformPassword(
				app.Logger, app.TPM, app.ServerKeyAttributes, app.PlatformKS.Backend())
		}
	}
	return nil
}

// Returns a new platform keychain given a "keystores" config,
// the key directory, security officer secret and user pin. An
// optional key backend may be provided to override the default
// storage location.
func (app *App) KeyringFromConfig(
	config *platform.KeyringConfig,
	fs afero.Fs,
	keyDir string,
	soPIN keystore.Password,
	userPIN keystore.Password,
	backend keystore.KeyBackend) (*platform.Keyring, error) {

	if app.PlatformKS == nil {
		app.InitPlatformKeyStore(soPIN, userPIN)
	}

	if backend == nil {
		backend = keystore.NewFileBackend(app.Logger, app.FS, keyDir)
	}
	factory, err := platform.NewKeyring(
		app.Logger,
		app.DebugSecretsFlag,
		app.FS,
		keyDir,
		app.Random,
		config,
		backend,
		app.BlobStore,
		app.SignerStore,
		app.TPM,
		app.PlatformKS,
		soPIN,
		userPIN)
	if err != nil {
		return nil, err
	}
	return factory, nil
}

// Creates a new x509 certificate store, with an optional blob
// store backend to override the default storage location.
func (app *App) NewCertificateStore(
	blobStore blob.BlobStorer) (certstore.CertificateStorer, error) {

	if blobStore == nil {
		blobStore = app.BlobStore
	}
	certStore, err := certstore.NewCertificateStore(
		app.Logger,
		blobStore)
	if err != nil {
		return nil, err
	}
	return certStore, nil
}

// Initialize the platform log file
func (app *App) InitLogFile(uid, gid int) afero.File {

	logFile := fmt.Sprintf("%s/%s.log", app.LogDir, Name)
	if err := app.FS.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}
	var f afero.File
	var err error
	f, err = app.FS.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	_, err = app.FS.Stat(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			_, err2 := app.FS.Create(logFile)
			if err2 != nil {
				log.Fatal(err2)
			}
		}
		log.Fatal(err)
	}
	if uid == 0 {
		if err = app.FS.Chown(logFile, uid, gid); err != nil {
			log.Fatal(err)
		}
		if app.DebugFlag {
			if err = app.FS.Chmod(logFile, os.ModePerm); err != nil {
				log.Fatal(err)
			}
		} else {
			if err = app.FS.Chmod(logFile, 0644); err != nil {
				log.Fatal(err)
			}
		}
		if err != nil {
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
	return TestConfigWithFS(afero.NewMemMapFs())
}

func TestConfigWithFS(fs afero.Fs) *App {

	Name = "trusted-platform"

	app := NewApp()
	app.DebugFlag = true
	app.DebugSecretsFlag = true

	configYaml, err := yaml.Marshal(DefaultConfig)
	if err != nil {
		panic(err)
	}

	fmt.Println("Test configuration:")
	fmt.Println(string(configYaml))

	app.FS = fs

	app.FS.MkdirAll("/var/log", os.ModePerm)
	afero.WriteFile(
		app.FS,
		fmt.Sprintf("%s/trusted-platform.log", DefaultConfig.LogDir),
		[]byte{},
		os.ModePerm)

	// Write app config to virtual fs
	configFile := fmt.Sprintf("%s/config.yaml", DefaultConfig.ConfigDir)
	app.FS.MkdirAll(DefaultConfig.ConfigDir, os.ModePerm)
	afero.WriteFile(app.FS, configFile, configYaml, os.ModePerm)

	// Configure viper
	viper.SetFs(app.FS)
	viper.AddConfigPath(DefaultConfig.ConfigDir)
	viper.SetConfigFile(configFile)

	// Debug info
	fmt.Println(viper.GetViper().ConfigFileUsed())
	if err = viper.ReadInConfig(); err != nil {
		panic(err)
	}

	if err := viper.Unmarshal(app); err != nil {
		panic(err)
	}

	app.Logger = logging.NewLogger(slog.LevelDebug, os.Stdout)

	return app
}

func parsePublicIPs(env Environment) (net.IP, net.IP, error) {

	if env == EnvTest {
		return nil, nil, nil
	}

	client := &http.Client{}

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
