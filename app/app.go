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

	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/util"
)

type App struct {
	Domain            string                      `yaml:"domain" json:"domain" mapstructure:"domain"`
	Hostmaster        string                      `yaml:"hostmaster" json:"hostmaster" mapstructure:"hostmaster"`
	CA                ca.CertificateAuthority     `yaml:"-" json:"-" mapstructure:"-"`
	TPM               tpm2.TrustedPlatformModule2 `yaml:"-" json:"-" mapstructure:"-"`
	CAConfig          ca.Config                   `yaml:"certificate-authority" json:"certificate_authority" mapstructure:"certificate-authority"`
	TPMConfig         tpm2.Config                 `yaml:"tpm" json:"tpm" mapstructure:"tpm"`
	AttestationConfig config.Attestation          `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	DebugFlag         bool                        `yaml:"debug" json:"debug" mapstructure:"debug"`
	DebugSecretsFlag  bool                        `yaml:"debug-secrets" json:"debug-secrets" mapstructure:"debug-secrets"`
	CertDir           string                      `yaml:"cert-dir" json:"cert_dir" mapstructure:"cert-dir"`
	ConfigDir         string                      `yaml:"config-dir" json:"config_dir" mapstructure:"config-dir"`
	DataDir           string                      `yaml:"data-dir" json:"data_dir" mapstructure:"data-dir"`
	LogDir            string                      `yaml:"log-dir" json:"log_dir" mapstructure:"log-dir"`
	Logger            *logging.Logger             `yaml:"-" json:"-" mapstructure:"-"`
	RuntimeUser       string                      `yaml:"runtime-user" json:"runtime_user" mapstructure:"runtime-user"`
	WebService        config.WebService           `yaml:"webservice" json:"webservice" mapstructure:"webservice"`
}

func NewApp() *App {
	return new(App)
}

type AppInitParams struct {
	Debug     bool
	LogDir    string
	ConfigDir string
	CertDir   string
}

func (app *App) Init(initParams *AppInitParams) *App {
	if initParams != nil {
		app.DebugFlag = initParams.Debug
		app.LogDir = initParams.LogDir
		app.ConfigDir = initParams.ConfigDir
		app.CertDir = initParams.CertDir
	}
	app.initConfig()
	app.initLogger()
	app.initTPM()
	app.initCA()
	if app.DebugFlag {
		logging.SetLevel(logging.DEBUG, "")
		app.Logger.Debug("Starting logger in debug mode...")
		for k, v := range viper.AllSettings() {
			app.Logger.Debugf("%s: %+v", k, v)
		}
	} else {
		logging.SetLevel(logging.INFO, "")
	}
	return app
}

func (app *App) initConfig() {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(app.ConfigDir)
	//viper.AddConfigPath(fmt.Sprintf("/etc/%s/", Name))
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
	//syslog, _ := logging.NewSyslogBackend(appName)
	backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(backends)
	if app.DebugFlag {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.ERROR, "")
	}
	app.Logger = logging.MustGetLogger(Name)
}

// Open a connection to the TPM, using an unauthenticated, unverified
// and un-attested connection. Use the software TPM simulator if enabled
// in the TPM configuration section.
func (app *App) initTPM() {
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
		app.Logger.Error("continuing as UNTRUSTED platform!")
	}
	app.TPM = tpm
}

// Initializes new Root and Intermediate Certificate Authorities according
// to the configuration. If this is the first time the CA is being initialized,
// new keys and certificates are created for the Root and Intermediate CAs
// and a web server certificate is issued for the configured domain by the
// Intermediate CA. If the CA and web server certificates have already been
// initialized, load them from persistent storage.
//
// If a Trusted Platform Module is found, use it as the random generator for
// the CA private keys. Use the TPM "Encrypt" configuration option to encrypt
// the session / bus communication between the CPU <-> TPM.
func (app *App) initCA() {

	// No need to keep the TPM open after Certificate Authority
	// initialization and local attestation is complete. Open and
	// close it again later when needed.
	defer app.TPM.Close()

	// Initalize TPM based random reader if present.
	// If "Encrypt" flag is set, the Read operation is
	// performed using an encrypted HMAC session between
	// the CPU <-> TPM.
	random := app.TPM.RandomReader()

	// Create new Root and Intermediate CA(s)
	_, intermediateCAs, err := ca.NewCA(
		app.Logger, app.CertDir, &app.CAConfig, random)
	if err != nil {
		app.Logger.Fatal(err)
	}

	intermediateIdentity := app.CAConfig.Identity[1]
	intermediateCN := intermediateIdentity.Subject.CommonName
	intermediateCA := intermediateCAs[intermediateCN]

	// Inject the CA into the TPM
	app.TPM.SetCertificateAuthority(intermediateCA)

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
		if _, err = intermediateCA.IssueCertificate(certReq); err != nil {
			app.Logger.Fatal(err)
		}
	}

	app.CA = intermediateCA

	// Initialize the TPM / Platform
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
