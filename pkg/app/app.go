package app

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	libtpm2 "github.com/google/go-tpm/tpm2"
	tpm2ks "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/tpm2"
)

var (
	ErrMissingEKWithoutEnabledCA        = errors.New("trusted-platform: EK certificate not found and unable to generate because the certificate authority is not enabled")
	ErrInvalidLocalAttestationSignature = errors.New("trusted-platform: local attestation signature verification failed")
	warnSimulatorWithEKCertHandle       = errors.New("trusted-platform: TPM Simulator w/ EK certificate (> 1024 bytes) configured for NV RAM storage. Using certificate store instead.")
	certPartition                       = "x509"

	ENV_DEV     Environment = "dev"
	ENV_PREPROD Environment = "preprod"
	ENV_PROD    Environment = "prod"
	ENV_TEST    Environment = "test"

	DefaultConfig = App{
		CAConfig:  &ca.DefaultConfig,
		ConfigDir: "/etc/trusted-platform",
		DatastoreConfig: &datastore.Config{
			Backend:          datastore.BACKEND_AFERO_MEMORY.String(),
			ConsistencyLevel: datastore.CONSISTENCY_LOCAL.String(),
			ReadBufferSize:   50,
			RootDir:          "trusted-data/datastore",
			Serializer:       serializer.SERIALIZER_YAML.String(),
		},
		LogDir:      "trusted-data/log",
		Logger:      logging.DefaultLogger(),
		PlatformDir: "trusted-data",
		Random:      rand.Reader,
		TPMConfig:   tpm2.DefaultConfig,
		WebService:  &webservice.DefaultConfigECDSA,
	}
)

type Environment string

func (e Environment) String() string {
	return string(e)
}

func ParseEnvironment(env string) Environment {
	switch env {
	case string(ENV_DEV):
		return ENV_DEV
	case string(ENV_PREPROD):
		return ENV_PREPROD
	case string(ENV_PROD):
		return ENV_PROD
	default:
		return Environment(env)
	}
}

type App struct {
	ACMEConfig          *acme.Config                `yaml:"acme" json:"acme" mapstructure:"acme"`
	Argon2              argon2.Argon2Config         `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	AttestationConfig   config.Attestation          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	BlobStore           blob.BlobStorer             `yaml:"-" json:"-" mapstructure:"-"`
	CA                  ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig            *ca.Config                  `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	ConfigDir           string                      `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	DatastoreConfig     *datastore.Config           `yaml:"datastore" json:"datastore" mapstructure:"datastore"`
	DebugFlag           bool                        `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag    bool                        `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	Domain              string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Environment         Environment                 `yaml:"-" json:"-" mapstructure:"-"`
	FS                  afero.Fs                    `yaml:"-" json:"-" mapstructure:"-"`
	Hostname            string                      `yaml:"hostname" json:"hostname" mapstructure:"hostname"`
	Hostmaster          string                      `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	ListenAddress       string                      `yaml:"listen" json:"listen" mapstructure:"listen"`
	LogDir              string                      `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	Logger              *logging.Logger             `yaml:"-" json:"-" mapstructure:"-"`
	PlatformDir         string                      `yaml:"platform-dir" json:"platform_dir" mapstructure:"platform-dir"`
	PlatformKS          tpm2ks.PlatformKeyStorer    `yaml:"-" json:"-" mapstructure:"-"`
	PlatformCertStore   certstore.CertificateStorer `yaml:"-" json:"-" mapstructure:"-"`
	Random              io.Reader                   `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser         string                      `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	SignerStore         keystore.SignerStorer       `yaml:"-" json:"-" mapstructure:"-"`
	ShutdownChan        chan bool                   `yaml:"-" json:"-" mapstructure:"-"`
	TPM                 tpm2.TrustedPlatformModule  `yaml:"-" json:"-" mapstructure:"-"`
	TPMConfig           tpm2.Config                 `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	WebService          *config.WebService          `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	ServerKeyAttributes *keystore.KeyAttributes     `yaml:"-" json:"-" mapstructure:"-"`
}

type AppInitParams struct {
	CADir         string
	ConfigDir     string
	Debug         bool
	DebugSecrets  bool
	Env           string
	EKCert        string
	Initialize    bool
	PlatformCA    int
	PlatformDir   string
	ListenAddress string
	LogDir        string
	Pin           []byte
	RuntimeUser   string
	SOPin         []byte
}

func NewApp() *App {
	app := new(App)
	app.ShutdownChan = make(chan bool, 1)
	return app
}

// Initialize the platform by loading the platform configuration
// file and initializing the platform logger.
func (app *App) Init(initParams *AppInitParams) (*App, error) {
	// Override config file with CLI options
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.DebugSecretsFlag = initParams.DebugSecrets
		app.PlatformDir = initParams.PlatformDir
		app.ConfigDir = initParams.ConfigDir
		app.LogDir = initParams.LogDir
		app.ListenAddress = initParams.ListenAddress
	}
	if app.FS == nil {
		app.FS = afero.NewOsFs()
	}
	if err := app.initConfig(initParams.Env); err != nil {
		return nil, err
	}
	app.initLogger()
	if err := app.initStores(); err != nil {
		return nil, err
	}

	soPIN := keystore.NewClearPassword(initParams.SOPin)
	userPIN := keystore.NewClearPassword(initParams.Pin)

	if initParams.Initialize {
		err := app.InitTPM(
			initParams.PlatformCA,
			initParams.SOPin,
			initParams.Pin)
		if err != nil {
			return nil, err
		}
		return app, nil
	}
	if err := app.OpenTPM(); err != nil {
		return app, err
	}
	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		return app, err
	}
	return app, nil
}

// Returns the platform publicly routable Fully Qualified Domain Name
func (app *App) FQDN() string {
	return fmt.Sprintf("%s.%s", app.Hostname, app.Domain)
}

// Read and parse the platform configuration file
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
	if app.DebugFlag {
		app.Logger = logging.DefaultLogger()
	} else {
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
		app.Logger = logging.NewLogger(slog.LevelError, file)
	}
	app.Logger.Info("platform configuration",
		slog.String("file", viper.ConfigFileUsed()))
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
				"app: generated new SO PIN: %s", soPIN)
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Compare(userPIN, []byte(keystore.DEFAULT_PASSWORD)) == 0 {
		userPIN = aesgcm.NewAESGCM(rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debugf(
				"app: generated new user PIN: %s", userPIN)
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
func (app *App) InitTPM(selectedCA int, soPIN, userPIN []byte) error {
	if err := app.OpenTPM(); err != nil {
		if err == tpm2.ErrNotInitialized {
			sopin, userpin, err := app.ParsePINs(soPIN, userPIN)
			if err != nil {
				return err
			}
			// Provision local TPM 2.0 per TCG recommended guidance
			if _, err := app.ProvisionPlatform(selectedCA, sopin, userpin); err != nil {
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
func (app *App) OpenTPM() error {
	if app.TPMConfig.EK == nil {
		return tpm2.ErrNotInitialized
	}
	path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
	backend := keystore.NewFileBackend(app.Logger, app.FS, path)
	if app.TPM == nil {
		var certStore certstore.CertificateStorer
		var err error
		if app.TPMConfig.EK.CertHandle == 0 {
			// Use the certificate store for the EK cert instead of NV RAM
			certStore, err = app.NewCertificateStore(nil)
			if err != nil {
				return err
			}
		}
		params := &tpm2.Params{
			Backend:      backend,
			BlobStore:    app.BlobStore,
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

// Provisions the TPM per the platform configuration file and
// TCG provisioning guidance. This operation assumes a new
// TPM whose hierarchy authorizations are empty. This function
// clears the TPM, set's the hierarchy authorizations, creates
// a persistent EK, Shared SRK, and if configured, an IAK and
// IDevID in accordance with TCG and IEEE 802.1 AR for secure
// device identification and authentication.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
func (app *App) ProvisionPlatform(
	selectedCA int,
	soPIN, userPIN keystore.Password) (*keystore.KeyAttributes, error) {

	fmt.Println("Provisioning TPM 2.0")

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
		if _, err := app.InitCA(selectedCA, soPIN, userPIN); err != nil {
			return nil, err
		}
	}

	// Get the Initial Attestation Key attributes
	iakAttrs, err := app.TPM.IAKAttributes()
	if err != nil {
		return nil, err
	}

	ekAttrs, err := app.TPM.EKAttributes()
	if err != nil {
		return nil, err
	}

	// Imports the TPM Endorsement Key into the Certificate Authority
	ekCert, err := app.ImportEndorsementKeyCertificate()
	if err != nil {
		return nil, err
	}

	var idevidAttrs *keystore.KeyAttributes

	// Create IAK & IDevID keys and certificates
	if app.TPMConfig.IAK != nil && app.TPMConfig.IDevID != nil {

		// Provision IDevID Key (IDevID)
		var tcgCSRIDevID *tpm2.TCG_CSR_IDEVID
		idevidAttrs, tcgCSRIDevID, err = app.TPM.CreateIDevID(iakAttrs, ekCert)
		if err != nil {
			return nil, err
		}
		keystore.DebugKeyAttributes(app.Logger, idevidAttrs)

		// Verify the TCG_CSR_IDEVID and receive the encrypted challenge
		credentialBlob, encryptedSecret, secret, err := app.CA.VerifyTCGCSRIDevID(
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
		_, err = app.CA.SignTCGCSRIDevID(idevidAttrs.CN, tcgCSRIDevID, &ca.CertificateRequest{
			KeyAttributes: ekAttrs,
			Valid:         0, // Valid until 99991231235959Z
			Subject: ca.Subject{
				CommonName:   idevidAttrs.CN,
				Organization: app.WebService.Certificate.Subject.Organization,
				Country:      app.WebService.Certificate.Subject.Country,
				Locality:     app.WebService.Certificate.Subject.Locality,
				Address:      app.WebService.Certificate.Subject.Address,
				PostalCode:   app.WebService.Certificate.Subject.PostalCode,
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

	// Create web services / device TLS certificate
	if err := app.InitWebServices(); err != nil {
		return nil, err
	}

	return idevidAttrs, nil
}

// Import TPM Endorsement Certificate - EK Credential Profile. Attempts
// to import the EK certificate from the TPM into the CA. If an EK
// certificate is not found, and the ek-gen options are set in the
// platform configuration file, a new EK certificate will be generated
// and imported into the TPM or certificate store.
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
				Valid:         36500, // 100 years
				Subject: ca.Subject{
					CommonName:   ekAttrs.CN,
					Organization: app.WebService.Certificate.Subject.Organization,
					Country:      app.WebService.Certificate.Subject.Country,
					Locality:     app.WebService.Certificate.Subject.Locality,
					Address:      app.WebService.Certificate.Subject.Address,
					PostalCode:   app.WebService.Certificate.Subject.PostalCode,
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

			// Generate new Endorsement Key x509 Certificate
			ekCert, err = app.CA.IssueEKCertificate(certReq, publicKey)
			if err != nil {
				return nil, err
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
func (app *App) LoadCA(userPIN keystore.Password) error {

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
		nil,
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
func (app *App) InitCA(
	selectedCA int,
	soPIN, userPIN keystore.Password) (ca.CertificateAuthority, error) {

	if app.TPM == nil {
		if err := app.OpenTPM(); err != nil {
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
		SelectedCA:   selectedCA,
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

// Check the CA for a TLS web server certificate. Create a new certificate
// if it doesn't exist.
func (app *App) InitWebServices() error {

	if app.WebService == nil {
		app.Logger.Warn("web services disabled")
		return nil
	}

	if app.TPMConfig.IDevID != nil &&
		app.TPMConfig.IDevID.CN == app.WebService.Certificate.Subject.CommonName {

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
		serverKeyAttrs, err := keystore.KeyAttributesFromConfig(app.WebService.Key)
		if err != nil {
			return err
		}
		serverKeyAttrs.Parent = app.PlatformKS.SRKAttributes()
		serverKeyAttrs.CN = app.WebService.Certificate.Subject.CommonName
		serverKeyAttrs.KeyType = keystore.KEY_TYPE_TLS
		serverKeyAttrs.TPMAttributes = &keystore.TPMAttributes{}
		app.ServerKeyAttributes = serverKeyAttrs
	}

	if app.DebugSecretsFlag || app.ServerKeyAttributes.Debug {
		app.Logger.Debug("Initializing web services")
		// app.Logger.Debugf("CA Private Key Password: %s", app.CA.CAKeyAttributes(nil).Password)
		app.Logger.Debugf("TLS Private Key Password: %s", app.ServerKeyAttributes.Password)
	}

	// Try to load the web services TLS cert
	pem, err := app.CA.PEM(app.ServerKeyAttributes)
	if err != nil {
		if err == certstore.ErrCertNotFound {

			// No cert, issue a platform server certificate for TLS encrypted web services
			certReq := ca.CertificateRequest{
				KeyAttributes: app.ServerKeyAttributes,
				Valid:         365, // days
				Subject: ca.Subject{
					// CommonName:   app.WebService.Certificate.Subject.CommonName,
					CommonName:   app.ServerKeyAttributes.CN,
					Organization: app.WebService.Certificate.Subject.Organization,
					Country:      app.WebService.Certificate.Subject.Country,
					Province:     app.WebService.Certificate.Subject.Province,
					Locality:     app.WebService.Certificate.Subject.Locality,
					Address:      app.WebService.Certificate.Subject.Address,
					PostalCode:   app.WebService.Certificate.Subject.PostalCode,
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

			// Issue the web server certificate
			der, err := app.CA.IssueCertificate(certReq)
			if err != nil {
				return err
			}

			if app.DebugFlag {
				pem, err = certstore.EncodePEM(der)
				if err != nil {
					return err
				}
				app.Logger.Debug("Web Server HTTPS certificate (PEM)")
				app.Logger.Debug(string(pem))
			}

		} else {
			return err
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
