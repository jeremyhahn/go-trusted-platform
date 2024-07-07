package app

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	logging "github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/hash"
	"github.com/jeremyhahn/go-trusted-platform/pkg/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/setup"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

var (
	ErrInvalidLocalAttestationSignature = errors.New("trusted-platform: local attestation signature verification failed")
)

type App struct {
	Domain               string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Hostmaster           string                      `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	CA                   ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	TPM                  tpm2.TrustedPlatformModule2 `yaml:"-" json:"-" mapstructure:"-"`
	PKCS11               pkcs11.PKCS11
	CAConfig             ca.Config          `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	TPMConfig            tpm2.Config        `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	PKCS11Config         pkcs11.Config      `yaml:"pkcs11" json:"pkcs11" mapstructure:"pkcs11"`
	AttestationConfig    config.Attestation `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	DebugFlag            bool               `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag     bool               `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	PlatformDir          string             `yaml:"platform-dir" json:"platform_dir" mapstructure:"platform-dir"`
	ConfigDir            string             `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	LogDir               string             `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	Logger               *logging.Logger    `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser          string             `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	Argon2               hash.Argon2Params  `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	WebService           config.WebService  `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	PasswordPolicy       string             `yaml:"password-policy" json:"password-policy" mapstructure:"password-policy"`
	RootPassword         string             `yaml:"root-password" json:"root_password" mapstructure:"root-password"`
	IntermediatePassword string             `yaml:"intermediate-password" json:"intermediate_password" mapstructure:"intermediate-password"`
	ServerPassword       string             `yaml:"server-password" json:"server_password" mapstructure:"server-password"`
	EKAuth               string             `yaml:"ek-auth" json:"ek_auth mapstructure:"ek-auth"`
	SRKAuth              string             `yaml:"srk-auth" json:"srk_auth mapstructure:"srk-auth"`
	cAPassword           string
}

func NewApp() *App {
	return new(App)
}

type AppInitParams struct {
	Debug                bool
	LogDir               string
	ConfigDir            string
	PlatformDir          string
	CADir                string
	CAPassword           string
	RootPassword         string
	IntermediatePassword string
	ServerPassword       string
	EKCert               string
	EKAuth               string
	SRKAuth              string
}

// Initialize the platform. Load the platform configuration file,
// create the logger, Root and Intermediate Certificate Authorities,
// and initialize the TPM.
func (app *App) Init(initParams *AppInitParams) *App {
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.PlatformDir = initParams.PlatformDir
		app.ConfigDir = initParams.ConfigDir
		app.LogDir = initParams.LogDir
		app.CAConfig.Home = initParams.CADir
	}
	app.initConfig()
	// Override initConfig with CLI options
	if initParams.CADir != "" {
		app.CAConfig.Home = initParams.CADir
	}
	if initParams.RootPassword != "" {
		app.RootPassword = initParams.RootPassword
	}
	if initParams.IntermediatePassword != "" {
		app.IntermediatePassword = initParams.IntermediatePassword
	}
	if initParams.ServerPassword != "" {
		app.ServerPassword = initParams.ServerPassword
	}
	if initParams.EKCert != "" {
		app.TPMConfig.EKCert = initParams.EKCert
	}
	if initParams.EKAuth != "" {
		app.SRKAuth = initParams.SRKAuth
	}
	if initParams.SRKAuth != "" {
		app.SRKAuth = initParams.SRKAuth
	}
	caPassword := initParams.CAPassword
	if caPassword == "" {
		if app.IntermediatePassword != "" {
			caPassword = app.IntermediatePassword
		} else {
			caPassword = app.RootPassword
		}
	}
	app.initLogger()
	app.initCA([]byte(caPassword))
	return app
}

// Read and parse the platform configuration file
func (app *App) initConfig() {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(app.ConfigDir)
	viper.AddConfigPath(fmt.Sprintf("$HOME/.%s/", Name))
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}

	if err := viper.Unmarshal(app); err != nil {
		log.Fatal(err)
	}

	log.Printf("Using configuration file: %s\n", viper.ConfigFileUsed())
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
	backends := logging.MultiLogger(stdoutFormatter, logFormatter)
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
}

// Opens a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. A TPM software simulator is used if enabled
// in the TPM section of the platform configuration file.
func (app *App) OpenTPM() error {
	if app.TPM == nil {
		var err error
		var tpm tpm2.TrustedPlatformModule2
		if app.TPMConfig.UseSimulator {
			tpm, err = tpm2.NewSimulation(
				app.Logger, app.DebugSecretsFlag, &app.TPMConfig, app.Domain)
		} else {
			tpm, err = tpm2.NewTPM2(
				app.Logger, app.DebugSecretsFlag, &app.TPMConfig, app.Domain)
		}
		if err != nil {
			app.Logger.Error(err)
			return err
		}
		app.TPM = tpm
	} else {
		if err := app.TPM.Open(); err != nil {
			app.Logger.Error(err)
			return err
		}
	}
	return nil
}

// Initializes the Certificate Authority.
//
// If the CA does not exist, Platform Setup begins to collect the Root and
// Intermediate Private Key passwords. New Root and Intermediate Certificate
// Authorities are created according to the platform configuration file - new
// RSA/ECC key pairs, an x509 signing certificates, and dedicated RSA encryption
// keys are created.
//
// If the CA is already initialized, the private key password must be supplied
// to log into the Trusted Platform, unseal the CA, and make it's private key
// available for signing and decryption operations.
//
// If a Trusted Platform Module (TPM) is found and entropy is enabled in the
// platform configuration file, then the TPM is used as the source of randomness
// for all entropy operations performed within the platform. Use the TPM "Encrypt"
// configuration option to encrypt the bus communication between the CPU <-> TPM.
//
// Any errors enountered during CA initialization are treated as Fatal.
func (app *App) initCA(caPassword []byte) {

	// Override passwords with user-defined passwords
	// in configuration file, if provided
	if app.RootPassword != "" {
		app.Logger.Warning("Loading Root Certificate Authority private key password from config file")
	}
	if app.IntermediatePassword != "" {
		app.Logger.Warning("Loading Intermediate Certificate Authority private key password from config file")
	}

	// Open the TPM. Close it after CA initialization is complete
	if err := app.OpenTPM(); err != nil {
		app.Logger.Fatal(err)
	}
	defer func() {
		if err := app.TPM.Close(); err != nil {
			app.Logger.Error(err)
		}
	}()

	// If TPM entropy is enabled in the config file,
	// the TPM RNG will be used as the source of
	// randomness, otherwise, the runtime rand.Reader
	// is used.
	// If "Encrypt" flag is set, the Read operation is
	// performed using a salted, encrypted HMAC session
	// between the CPU <-> TPM bus.
	random := app.TPM.RandomReader()

	// Set the CA password policy to the global password
	// password policy if set to "inherit"
	if app.CAConfig.PasswordPolicy == "inherit" {
		app.CAConfig.PasswordPolicy = app.PasswordPolicy
	}

	// Instantiate Root and Intermediate CA(s)
	params := ca.CAParams{
		Debug:                app.DebugFlag,
		DebugSecrets:         app.DebugSecretsFlag,
		Logger:               app.Logger,
		Config:               &app.CAConfig,
		Password:             []byte(caPassword),
		SelectedIntermediate: 1,
		Random:               random,
	}
	rootCA, intermediateCA, err := ca.NewCA(params)
	if err != nil {

		if err == ca.ErrNotInitialized {

			// Run platform setup to initialize the CA
			platformSetup := setup.NewPlatformSetup(
				Name,
				app.Logger,
				app.PasswordPolicy,
				app.RootPassword,
				app.IntermediatePassword,
				app.CAConfig,
				rootCA,
				intermediateCA,
				app.TPM)

			// Run platform setup
			caPassword = platformSetup.Setup()

			// Inject the CA into the TPM instance
			app.TPM.SetCertificateAuthority(intermediateCA)

			// Perform local TPM quote, sign and store to CA blob storage
			if _, err := app.TPM.LocalQuote(true, caPassword); err != nil {
				app.Logger.Fatal(err)
			}

			// Generate a new TLS server certificate for the
			// web server. Any errors are treated as fatal.
			app.InitWebServices(
				intermediateCA,
				caPassword,
				[]byte(app.ServerPassword))

		} else {

			// Set up the platform authenticator (PKCS #8)
			// TODO: PKCS #11
			pkcs8Authenticator := auth.NewPKCS8Authenticator(
				app.Logger,
				intermediateCA,
				[]byte(app.RootPassword),
				[]byte(app.IntermediatePassword))

			if err := pkcs8Authenticator.Authenticate(caPassword); err != nil {
				app.Logger.Fatal(err)
			}

			// Perform local system attestation
			if err := app.TPM.AttestLocal(caPassword); err != nil {
				// TODO: Re-seal the CA, run intrusion detection handlers,
				// wipe the file system, etc in an attempt to mitigate the
				// attack or unauthorized / unexpected changes.
				app.Logger.Fatal(ErrInvalidLocalAttestationSignature)
			}
		}

		// Inject the CA into the TPM instance
		app.TPM.SetCertificateAuthority(intermediateCA)

	} else {

		// Inject the CA into the TPM instance
		app.TPM.SetCertificateAuthority(intermediateCA)
	}

	if caPassword == nil {
		app.Logger.Warningf("trusted-platform: proceeding as UNTRUSTED, INSECURE platform")
	}
	if app.DebugSecretsFlag {
		app.Logger.Debug("Starting platform using the following credentials:")
		app.Logger.Debugf("Root CA: %s", app.RootPassword)
		app.Logger.Debugf("Intermediate CA: %s", app.IntermediatePassword)
		app.Logger.Debugf("Platform CA: %s", caPassword)
	}

	// Set the platform CA
	app.CA = intermediateCA

	// Initialize the TPM
	if err := app.TPM.Init([]byte(app.SRKAuth), []byte(caPassword)); err != nil {
		app.Logger.Fatal(err)
	}
}

// Check the CA for a TLS web server certificate. Create a new certificate
// if it doesn't exist. Any encountered errors are treated as Fatal.
func (app *App) InitWebServices(
	_ca ca.CertificateAuthority,
	caPassword, serverPassword []byte) {

	if app.DebugSecretsFlag {
		app.Logger.Debug("Initializing web services")
		app.Logger.Debugf("CA Private Key Password: %s", caPassword)
		app.Logger.Debugf("TLS Private Key Password: %s", serverPassword)
	}

	// Try to load the web services TLS cert
	_, err := _ca.PEM(app.Domain)
	if err != nil {

		// No cert, issue a platform server certificate for TLS encrypted web services
		certReq := ca.CertificateRequest{
			Valid: 365, // days
			Subject: ca.Subject{
				CommonName:   app.Domain,
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
		if app.CAConfig.IncludeLocalhostInSANS {
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
		if _, err = _ca.IssueCertificate(
			certReq,
			[]byte(caPassword),
			[]byte(serverPassword)); err != nil {
			app.Logger.Fatal(err)
		}
	}
}

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

// Reads STDIN and returns the input as []byte
func (app *App) ReadPassword() []byte {
	fmt.Printf("%s> ", Name)
	data, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		app.Logger.Fatal(err)
	}
	return data
}

// Prompts for the Certificate Authority password
func (app *App) CAPasswordPrompt() []byte {
	fmt.Println()
	fmt.Println("Certificate Authority Password:")
	fmt.Println("")
	return app.ReadPassword()
}

// Prompts for input via STDIN using the given
// message as the user prompt.
func (app *App) Prompt(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(message)
	fmt.Printf("%s $ ", Name)
	str, err := reader.ReadString('\n')
	if err != nil {
		app.Logger.Fatal(err)
	}
	return str
}
