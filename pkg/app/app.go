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
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	logging "github.com/op/go-logging"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/crypto/argon2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/blob"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

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
)

type Environment string

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
	Argon2              argon2.Argon2Config         `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	AttestationConfig   config.Attestation          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	BlobStore           blob.BlobStorer             `yaml:"-" json:"-" mapstructure:"-"`
	CA                  ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig            *ca.Config                  `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	ConfigDir           string                      `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	DebugFlag           bool                        `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag    bool                        `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	Domain              string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Environment         Environment                 `yaml:"-" json:"-" mapstructure:"-"`
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
	TPM                 tpm2.TrustedPlatformModule  `yaml:"-" json:"-" mapstructure:"-"`
	TPMConfig           tpm2.Config                 `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	WebService          config.WebService           `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	ServerKeyAttributes *keystore.KeyAttributes     `yaml:"-" json:"-" mapstructure:"-"`
}

func NewApp() *App {
	return new(App)
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

// Initialize the platform by loading the platform configuration
// file and initializing the platform logger.
func (app *App) Init(initParams *AppInitParams) *App {
	// Override config file with CLI options
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.DebugSecretsFlag = initParams.DebugSecrets
		app.PlatformDir = initParams.PlatformDir
		app.ConfigDir = initParams.ConfigDir
		app.LogDir = initParams.LogDir
		app.ListenAddress = initParams.ListenAddress
	}
	app.initConfig(initParams.Env)
	app.initLogger()
	app.initStores()

	soPIN := keystore.NewClearPassword(initParams.SOPin)
	userPIN := keystore.NewClearPassword(initParams.Pin)

	if initParams.Initialize {
		app.InitTPM(
			initParams.PlatformCA,
			initParams.SOPin,
			initParams.Pin)
		return app
	}

	if err := app.OpenTPM(); err != nil {
		app.Logger.Fatal(err)
	}
	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		app.Logger.Fatal(err)
	}
	if app.CAConfig != nil {
		app.LoadCA(initParams.PlatformCA, userPIN)
	}
	return app
}

// Returns the platform publicly routable Fully Qualified Domain Name
func (app *App) FQDN() string {
	return fmt.Sprintf("%s.%s", app.Hostname, app.Domain)
}

// Read and parse the platform configuration file
func (app *App) initConfig(env string) {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(app.ConfigDir)
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
				panic(err)
			}
		} else {
			panic(err)
		}
	}

	if err := viper.Unmarshal(app); err != nil {
		panic(err)
	}
}

// Creates a new file and STDOUT logger. If the global DebugFlag is set,
// the logger is initialized in debug mode, executing all logger.Debug*
// statements.
func (app *App) initLogger() {
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	f := app.InitLogFile(os.Getuid(), os.Getgid())
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	logfile := logging.NewLogBackend(f, "", log.Lshortfile)
	logFormatter := logging.NewBackendFormatter(logfile, logFormat)
	stdoutFormatter := logging.NewBackendFormatter(stdout, logFormat)
	//syslog, _ := logging.NewSyslogBackend(appName)
	var backends logging.LeveledBackend
	if app.DebugFlag {
		backends = logging.MultiLogger(stdoutFormatter, logFormatter)
	} else {
		backends = logging.MultiLogger(logFormatter)
	}
	logging.SetBackend(backends)
	logger := logging.MustGetLogger(Name)
	if app.DebugFlag {
		logging.SetLevel(logging.DEBUG, "")
		logger.Debug("Starting logger in debug mode...")
		for k, v := range viper.AllSettings() {
			logger.Debugf("%s: %+v", k, v)
		}
	} else {
		logging.SetLevel(logging.ERROR, "")
	}
	app.Logger = logging.MustGetLogger(Name)

	app.Logger.Infof("Using configuration file: %s\n", viper.ConfigFileUsed())
}

// Initialize blob and signer stores
func (app *App) initStores() {
	blobstore, err := blob.NewFSBlobStore(app.Logger, app.PlatformDir, nil)
	if err != nil {
		app.Logger.Fatal(err)
	}
	app.BlobStore = blobstore
	app.SignerStore = keystore.NewSignerStore(app.BlobStore)
	cs, err := app.NewCertificateStore(app.BlobStore)
	if err != nil {
		app.Logger.Fatal(err)
	}
	app.PlatformCertStore = cs
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
		soPIN = aesgcm.NewAESGCM(
			app.Logger, app.DebugSecretsFlag, rand.Reader).GenerateKey()

		if app.DebugSecretsFlag {
			app.Logger.Debugf(
				"app: generated new SO PIN: %s", soPIN)
		}
	}

	// Generate random SO pin if its set to the default password
	if bytes.Compare(userPIN, []byte(keystore.DEFAULT_PASSWORD)) == 0 {
		userPIN = aesgcm.NewAESGCM(
			app.Logger, app.DebugSecretsFlag, rand.Reader).GenerateKey()

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
func (app *App) InitTPM(selectedCA int, soPIN, userPIN []byte) {
	if err := app.OpenTPM(); err != nil {
		if err == tpm2.ErrNotInitialized {
			sopin, userpin, err := app.ParsePINs(soPIN, userPIN)
			if err != nil {
				app.Logger.Fatal(err)
			}
			// Provision local TPM 2.0 per TCG recommended guidance
			app.ProvisionPlatform(selectedCA, sopin, userpin)
		} else {
			app.Logger.Fatal(err)
		}
	}
}

// Opens a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. A TPM software simulator is used if enabled
// in the TPM section of the platform configuration file.
func (app *App) OpenTPM() error {
	path := fmt.Sprintf("%s/platform/keystore", app.PlatformDir)
	backend := keystore.NewFileBackend(app.Logger, path)
	if app.TPM == nil {
		var certStore certstore.CertificateStorer
		var err error
		if app.TPMConfig.EK.CertHandle == 0 {
			// Use the certificate store for the EK cert instead of NV RAM
			certStore, err = app.NewCertificateStore(nil)
			if err != nil {
				app.Logger.Fatal(err)
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
		backend := keystore.NewFileBackend(app.Logger, path)
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
	soPIN, userPIN keystore.Password) *keystore.KeyAttributes {

	fmt.Println("Provisioning TPM 2.0")

	// Provision the TPM
	if err := app.TPM.Provision(soPIN); err != nil {
		app.Logger.Fatal(err)
	}

	// Provision the platform TPM 2.0 key store
	if err := app.InitPlatformKeyStore(soPIN, userPIN); err != nil {
		app.Logger.Fatal(err)
	}

	// Initialize the Certificate Authorities
	if app.CAConfig != nil {
		app.InitCA(selectedCA, soPIN, userPIN)
	}

	// Get the Initial Attestation Key attributes
	iakAttrs, err := app.TPM.IAKAttributes()
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Imports the TPM Endorsement Key into the Certificate Authority
	ekCert := app.ImportEndorsementKey()

	var idevidAttrs *keystore.KeyAttributes

	// Create IAK & IDevID keys and certificates
	if app.TPMConfig.IAK != nil && app.TPMConfig.IDevID != nil {

		// Provision IDevID Key (IDevID)
		var tcgCSRIDevID *tpm2.TCG_CSR_IDEVID
		idevidAttrs, tcgCSRIDevID, err = app.TPM.CreateIDevID(iakAttrs, ekCert)
		if err != nil {
			app.Logger.Fatal(err)
		}
		keystore.DebugKeyAttributes(app.Logger, idevidAttrs)

		// Verify the TCG_CSR_IDEVID and receive the encrypted challenge
		credentialBlob, encryptedSecret, secret, err := app.CA.VerifyTCGCSRIDevID(
			tcgCSRIDevID, iakAttrs.SignatureAlgorithm)
		if err != nil {
			app.Logger.Fatal(err)
		}

		// Release the secret using TPM2_ActivateCredential and
		// verify the secrets match
		releasedCertInfo, err := app.TPM.ActivateCredential(
			credentialBlob, encryptedSecret)
		if err != nil {
			app.Logger.Fatal(err)
		}
		if bytes.Compare(releasedCertInfo, secret) != 0 {
			app.Logger.Fatal(tpm2.ErrInvalidActivationCredential)
		}

		// Sign TCG_CSR_IDEVID, create IDevID x509 device certificate
		_, err = app.CA.SignTCGCSRIDevID(idevidAttrs.CN, tcgCSRIDevID, nil)
		if err != nil {
			app.Logger.Fatal(err)
		}

		// Perform local TPM Quote
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

	// Build web service key attributes
	serverKeyAttrs, err := keystore.KeyAttributesFromConfig(
		app.WebService.Key)
	if err != nil {
		app.Logger.Fatal(err)
	}
	serverKeyAttrs.Parent = app.PlatformKS.SRKAttributes()
	serverKeyAttrs.CN = app.WebService.Certificate.Subject.CommonName
	serverKeyAttrs.KeyType = keystore.KEY_TYPE_TLS
	serverKeyAttrs.TPMAttributes = &keystore.TPMAttributes{}
	app.ServerKeyAttributes = serverKeyAttrs

	// Create web services / device TLS certificate
	// TODO: Replace this certificate with IDevID / LDevID
	app.InitWebServices()

	return serverKeyAttrs
}

// Import TPM Endorsement Certificate - EK Credential Profile. Attempts
// to import the EK certificate from the TPM into the CA. If an EK
// certificate is not found, and the ek-gen options are set in the
// platform configuration file, a new EK certificate will be generated
// and imported into the TPM or certificate store.
func (app *App) ImportEndorsementKey() *x509.Certificate {

	if app.CA == nil {
		app.Logger.Fatal(ErrMissingEKWithoutEnabledCA)
	}

	ekAttrs, err := app.TPM.EKAttributes()
	if err != nil {
		app.Logger.Fatal(err)
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
				app.Logger.Fatal(
					"unsupported TPM EK algorithm %s",
					app.TPMConfig.EK.KeyAlgorithm)
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
				app.Logger.Fatal(err)
			}

			certstore.DebugCertificate(app.Logger, ekCert)

			// Write the EK cert to TPM NV RAM
			hierarchyAuth, err := ekAttrs.TPMAttributes.HierarchyAuth.Bytes()
			if err != nil {
				app.Logger.Fatal(err)
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
						app.Logger.Warning(warnSimulatorWithEKCertHandle)
					}
				} else {
					app.Logger.Error(err)
				}
			}
			return ekCert

		} else {
			app.Logger.Fatal(err)
		}
	}
	err = app.CA.ImportEndorsementKeyCertificate(ekAttrs, ekCert.Raw)
	if err != nil {
		app.Logger.Fatal(err)
	}

	return ekCert
}

// Loads an initialized Certificate Authority
func (app *App) LoadCA(selectedCA int, userPIN keystore.Password) {

	params := &ca.CAParams{
		Debug:        app.DebugFlag,
		DebugSecrets: app.DebugSecretsFlag,
		Logger:       app.Logger,
		Config:       *app.CAConfig,
		SelectedCA:   selectedCA,
		Random:       app.TPM,
		BlobStore:    app.BlobStore,
		SignerStore:  app.SignerStore,
		TPM:          app.TPM,
	}
	params.Identity = app.CAConfig.Identity[selectedCA]

	caRoot := ca.HomeDirectory(app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, caRoot, &certPartition)
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		params.Logger.Fatal(err)
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyChainConfig.CN = params.Identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	backend := keystore.NewFileBackend(params.Logger, caRoot)

	// Create keychain for the CA
	keychain, err := app.KeyChainFromConfig(
		params.Identity.KeyChainConfig,
		caRoot,
		nil,
		userPIN,
		backend)
	if err != nil {
		app.Logger.Fatal(err)
	}
	params.KeyChain = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	if selectedCA == 0 {

		parentCA, err := ca.NewParentCA(params)
		if err != nil {
			app.Logger.Fatal(err)
		} else {
			app.CA = parentCA
		}
	} else {
		params.Identity = app.CAConfig.Identity[selectedCA]
		intermediateCA, err := ca.NewIntermediateCA(params)
		if err != nil {
			app.Logger.Fatal(err)
		}
		if err := intermediateCA.Load(); err != nil {
			app.Logger.Fatal(err)
		}
		app.CA = intermediateCA
	}
}

// Initializes all Certificate Authorities provided in the
// platform configuration file and returns the selected
// "Platform CA" as the default CA used for Platform operations.
func (app *App) InitCA(
	selectedCA int,
	soPIN, userPIN keystore.Password) ca.CertificateAuthority {

	if app.TPM == nil {
		if err := app.OpenTPM(); err != nil {
			app.Logger.Fatal(err)
		}
	}

	var platformCA ca.CertificateAuthority

	if len(app.CAConfig.Identity) == 0 {
		app.Logger.Fatal(ca.ErrInvalidConfig)
	}

	params := &ca.CAParams{
		Debug:        app.DebugFlag,
		DebugSecrets: app.DebugSecretsFlag,
		Logger:       app.Logger,
		Config:       *app.CAConfig,
		SelectedCA:   selectedCA,
		Random:       app.TPM,
		BlobStore:    app.BlobStore,
		SignerStore:  app.SignerStore,
		TPM:          app.TPM,
	}

	rootCA := app.InitRootCA(params, soPIN, userPIN)

	for i := 1; i < len(app.CAConfig.Identity); i++ {
		thisCA := app.CAConfig.Identity[i]
		intermediateCA := app.InitIntermediateCA(
			params, thisCA, rootCA, soPIN, userPIN)
		if i == app.CAConfig.PlatformCA {
			platformCA = intermediateCA
		}
	}

	app.CA = platformCA

	return platformCA
}

// Initializes a Root / Parent Certificate Authority
func (app *App) InitRootCA(
	params *ca.CAParams,
	soPIN, userPIN keystore.Password) ca.CertificateAuthority {

	fmt.Println("Initializing Root / Parent Certificate Authority")

	params.Identity = app.CAConfig.Identity[0]

	caRoot := ca.HomeDirectory(app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, caRoot, &certPartition)
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		params.Logger.Fatal(err)
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyChainConfig.CN = params.Identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	keyBackend := keystore.NewFileBackend(params.Logger, caRoot)

	// Create keychain for the Parent / Root CA
	keychain, err := app.KeyChainFromConfig(
		params.Identity.KeyChainConfig,
		caRoot,
		soPIN,
		userPIN,
		keyBackend)
	if err != nil {
		app.Logger.Fatal(err)
	}
	params.KeyChain = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	// Creates a new Parent / Root Certificate Authority
	rootCA, err := ca.NewParentCA(params)
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Initialize the CA by creating new keys and certificates
	if err := rootCA.Init(nil); err != nil {
		app.Logger.Fatal(err)
	}

	// Set the Root CA as the platform CA if it's the only
	// one configured
	if len(app.CAConfig.Identity) == 1 {
		app.CA = rootCA
	}

	return rootCA
}

// Initializes an Intermediate Certificate Authority
func (app *App) InitIntermediateCA(
	caParams *ca.CAParams,
	identity ca.Identity,
	parentCA ca.CertificateAuthority,
	soPIN, userPIN keystore.Password) ca.CertificateAuthority {

	fmt.Println("Initializing Intermediate Certificate Authority")

	params := *caParams
	params.Identity = identity

	caRoot := ca.HomeDirectory(app.PlatformDir,
		params.Identity.Subject.CommonName)

	params.Backend = keystore.NewFileBackend(params.Logger, caRoot)

	// Create x509 certificate store backend
	certBackend, err := blob.NewFSBlobStore(
		app.Logger, caRoot, &certPartition)
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Create the x509 certificate store
	certStore, err := app.NewCertificateStore(certBackend)
	if err != nil {
		params.Logger.Fatal(err)
	}
	params.CertStore = certStore

	// Set the name of all of the key stores to the CA common name
	params.Identity.KeyChainConfig.CN = identity.Subject.CommonName

	// Create a new key store file backend under the CA home directory
	backend := keystore.NewFileBackend(params.Logger, caRoot)

	// Create keychain for the Intermediate CA
	keychain, err := app.KeyChainFromConfig(
		params.Identity.KeyChainConfig,
		caRoot,
		soPIN,
		userPIN,
		backend)
	if err != nil {
		app.Logger.Fatal(err)
	}
	params.KeyChain = keychain
	params.TPM = app.TPM
	params.Random = app.Random
	params.Debug = app.DebugFlag
	params.DebugSecrets = app.DebugSecretsFlag

	// Create the new Intermediate CA
	intermediateCA, err := ca.NewIntermediateCA(&params)
	if err != nil {
		app.Logger.Fatal(err)
	}

	// Initialize the CA by creating new keys and certificates, using
	// the parentCA to sign for this new intermediate
	if err := intermediateCA.Init(parentCA); err != nil {
		app.Logger.Fatal(err)
	}

	// Set the platform CA
	app.CA = intermediateCA

	return intermediateCA
}

// Performs a local TPM 2.0 attestation
func (app *App) AttestLocal(serverAttrs *keystore.KeyAttributes) (tpm2.Quote, []byte, error) {
	fmt.Println("Performing local attestation")
	quote, nonce, err := app.TPM.LocalQuote(serverAttrs)
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
// if it doesn't exist. Any encountered errors are treated as Fatal.
func (app *App) InitWebServices() {

	if app.DebugSecretsFlag {
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
					CommonName:   app.WebService.Certificate.Subject.CommonName,
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

			// Include localhost SANS DNS, IPs, and and root email if config
			// is set to sans-include-localhost: true.
			if app.CAConfig.IncludeLocalhostSANS {
				// Parse list of usable local IPs
				ips, err := util.LocalAddresses()
				if err != nil {
					app.Logger.Fatal(err)
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
				app.Logger.Fatal(err)
			}

			if app.DebugFlag {
				pem, err = certstore.EncodePEM(der)
				if err != nil {
					app.Logger.Fatal(err)
				}
				app.Logger.Debug("Web Server HTTPS certificate (PEM)")
				app.Logger.Debug(string(pem))
			}

		} else {
			app.Logger.Fatal(err)
		}
	}
}

// Returns a new platform keychain given a "keystores" config,
// the key directory, security officer secret and user pin. An
// optional key backend may be provided to override the default
// storage location.
func (app *App) KeyChainFromConfig(
	config *platform.KeyChainConfig,
	keyDir string,
	soPIN keystore.Password,
	userPIN keystore.Password,
	backend keystore.KeyBackend) (*platform.KeyChain, error) {

	if app.PlatformKS == nil {
		app.InitPlatformKeyStore(soPIN, userPIN)
	}

	if backend == nil {
		backend = keystore.NewFileBackend(app.Logger, keyDir)
	}
	factory, err := platform.NewKeyChain(
		app.Logger,
		app.DebugSecretsFlag,
		keyDir,
		app.TPM,
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
func (app *App) InitLogFile(uid, gid int) *os.File {
	logFile := fmt.Sprintf("%s/%s.log", app.LogDir, Name)
	if err := os.MkdirAll(app.LogDir, os.ModePerm); err != nil {
		log.Fatal(err)
	}
	var f *os.File
	var err error
	f, err = os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	_, err = os.Stat(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			_, err2 := os.Create(logFile)
			if err2 != nil {
				log.Fatal(err2)
			}
		}
		log.Fatal(err)
	}
	if uid == 0 {
		if err = os.Chown(logFile, uid, gid); err != nil {
			log.Fatal(err)
		}
		if app.DebugFlag {
			if err = os.Chmod(logFile, os.ModePerm); err != nil {
				log.Fatal(err)
			}
		} else {
			if err = os.Chmod(logFile, 0644); err != nil {
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
