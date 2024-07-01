package app

import (
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

	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/hash"
	"github.com/jeremyhahn/go-trusted-platform/platform/auth"
	"github.com/jeremyhahn/go-trusted-platform/platform/setup"
	"github.com/jeremyhahn/go-trusted-platform/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/util"
)

type App struct {
	Domain               string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Hostmaster           string                      `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	CA                   ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	TPM                  tpm2.TrustedPlatformModule2 `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig             ca.Config                   `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	TPMConfig            tpm2.Config                 `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	AttestationConfig    config.Attestation          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	DebugFlag            bool                        `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag     bool                        `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	PlatformDir          string                      `yaml:"platform-dir" json:"platform_dir" mapstructure:"platform-dir"`
	ConfigDir            string                      `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	LogDir               string                      `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	Logger               *logging.Logger             `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser          string                      `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	Argon2               hash.Argon2Params           `yaml:"argon2" json:"argon2" mapstructure:"argon2"`
	WebService           config.WebService           `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
	PasswordPolicy       string                      `yaml:"password-policy" json:"password-policy" mapstructure:"password-policy"`
	RootPassword         string                      `yaml:"root-password" json:"root_password" mapstructure:"root-password"`
	IntermediatePassword string                      `yaml:"intermediate-password" json:"intermediate_password" mapstructure:"intermediate-password"`
}

func NewApp() *App {
	return new(App)
}

type AppInitParams struct {
	Debug             bool
	LogDir            string
	ConfigDir         string
	PlatformDir       string
	CADir             string
	CAPassword        []byte
	ServerTLSPassword []byte
}

func (app *App) Init(initParams *AppInitParams) *App {
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.PlatformDir = initParams.PlatformDir
		app.ConfigDir = initParams.ConfigDir
		app.LogDir = initParams.LogDir
		app.CAConfig.Home = initParams.CADir
	}
	app.initConfig()
	// Overwrite config with CLI options
	app.CAConfig.Home = initParams.CADir
	app.initLogger()
	if initParams.CAPassword == nil || len(initParams.CAPassword) == 0 {
		app.promptForCAPassword()
		initParams.CAPassword = app.PasswordPrompt()
	}
	if initParams.ServerTLSPassword == nil || len(initParams.ServerTLSPassword) == 0 {
		app.promptForServerTLSPassword()
		initParams.ServerTLSPassword = app.PasswordPrompt()
	}
	app.initCA(initParams.CAPassword, initParams.ServerTLSPassword)
	return app
}

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

// Open a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. Use the software TPM simulator if enabled
// in the TPM configuration section.
func (app *App) openTPM(caPassword []byte) {
	var err error
	var tpm tpm2.TrustedPlatformModule2
	if app.TPMConfig.UseSimulator {
		tpm, err = tpm2.NewSimulation(
			app.Logger, app.DebugSecretsFlag, &app.TPMConfig, caPassword, app.Domain)
	} else {
		tpm, err = tpm2.NewTPM2(
			app.Logger, app.DebugSecretsFlag, &app.TPMConfig, caPassword, app.Domain)
	}
	if err != nil {
		app.Logger.Error(err)
		app.Logger.Error("continuing as UNTRUSTED platform!")
	}
	app.TPM = tpm
}

// Initializes new Root and Intermediate Certificate Authorities according
// to the configuration. If this is the first time the CA is being initialized,
// new keys and certificates are created for the Root and Intermediate CAs
// and a web server certificate is issued for the configured domain by the
// Intermediate CA. If the CA has already been initialized, it's keys and signing
// certificate are reloaded from persistent storage.
//
// If a Trusted Platform Module is found and entropy is enabled in the
// configuration then it's used as the source of randomness for all random
// operations in the platform. Use the TPM "Encrypt" configuration option
// to encrypt the bus communication between the CPU <-> TPM.
func (app *App) initCA(caPassword, serverTLSPassword []byte) {

	// Override passwords with user-defined passwords
	// in configuration file, if provided
	rootPassword := caPassword
	intermediatePassword := caPassword
	if app.RootPassword != "" {
		app.Logger.Warning("Loading Root Certificate Authority private key password from configuration file")
		rootPassword = []byte(app.RootPassword)
	}
	if app.IntermediatePassword != "" {
		app.Logger.Warning("Loading Intermediate Certificate Authority private key password from configuration file")
		intermediatePassword = []byte(app.IntermediatePassword)
		app.openTPM(intermediatePassword)
	} else {
		app.openTPM(caPassword)
	}
	defer app.TPM.Close()

	// Initalize TPM based random reader if present.
	// If "Encrypt" flag is set, the Read operation is
	// performed using an encrypted HMAC session between
	// the CPU <-> TPM.
	random := app.TPM.RandomReader()

	// Set the CA password policy to the global password
	// password policy if set to "inherit"
	if app.CAConfig.PasswordPolicy == "inherit" {
		app.CAConfig.PasswordPolicy = app.PasswordPolicy
	}

	// Create new Root and Intermediate CA(s)
	params := ca.CAParams{
		Debug:                app.DebugFlag,
		DebugSecrets:         app.DebugSecretsFlag,
		Logger:               app.Logger,
		Config:               &app.CAConfig,
		Password:             caPassword,
		SelectedIntermediate: 1,
		Random:               random,
	}
	rootCA, intermediateCA, err := ca.NewCA(params)

	// Inject the CA into the TPM
	app.TPM.SetCertificateAuthority(intermediateCA)

	// Start platform setup if the CA hasn't been initialized
	if err != nil {
		if err == ca.ErrNotInitialized {
			// Set up the platform authenticator (PKCS8)
			pkcs8Authenticator := auth.NewPKCS8Authenticator(
				app.Logger,
				intermediateCA,
				app.RootPassword,
				app.IntermediatePassword)

			// Run platform setup using the PKCS8 authenticator
			platformSetup := setup.NewPlatformSetup(
				app.Logger,
				app.PasswordPolicy,
				rootPassword,
				intermediatePassword,
				app.CAConfig,
				rootCA,
				intermediateCA,
				app.TPM,
				pkcs8Authenticator)

			// Run platform setup
			platformSetup.Setup(caPassword)
		} else {
			app.Logger.Fatal(err)
		}
	}

	// Platform Setup uses nil password to load
	// passwords from file. This sets the regular
	// password variable to the password in the config.
	if app.IntermediatePassword != "" {
		caPassword = intermediatePassword
	}

	// Try to load the web services TLS cert
	_, err = intermediateCA.PEM(app.Domain)
	if err != nil {

		// Issue a platform server certificate for TLS encrypted web services
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
		if _, err = intermediateCA.IssueCertificate(certReq, caPassword, serverTLSPassword); err != nil {
			app.Logger.Fatal(err)
		}
	}

	app.CA = intermediateCA

	// Initialize the TPM
	if err := app.TPM.Init(); err != nil {
		app.Logger.Fatal(err)
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

// Prompts for CA password via STDIN
func (app *App) PasswordPrompt() []byte {
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		app.Logger.Fatal(err)
	}
	return password
}

// Outputs
func (app *App) promptForCAPassword() {
	fmt.Println("\nCertifiate Authority private key password:")
	fmt.Println("")
}

func (app *App) promptForServerTLSPassword() {
	fmt.Println("\nServer TLS private key password")
	fmt.Println("")
}
