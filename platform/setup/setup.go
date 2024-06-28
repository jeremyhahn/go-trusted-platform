package setup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"regexp"
	"syscall"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/jeremyhahn/go-trusted-platform/common"
	"github.com/jeremyhahn/go-trusted-platform/platform/auth"
	"github.com/jeremyhahn/go-trusted-platform/tpm2"
	"github.com/op/go-logging"
	"golang.org/x/term"
)

type PlatformSetup interface {
	Setup(password []byte)
}

type Setup struct {
	logger               *logging.Logger
	passwordPolicy       *regexp.Regexp
	rootPassword         []byte
	intermediatePassword []byte
	caConfig             ca.Config
	rootCA               ca.CertificateAuthority
	intermediateCA       ca.CertificateAuthority
	tpm                  tpm2.TrustedPlatformModule2
	authenticator        auth.PlatformAuthenticator
}

// Creates a new Platform Setup
func NewPlatformSetup(
	logger *logging.Logger,
	passwordPolicyPattern string,
	rootPassword, intermediatePassword []byte,
	caConfig ca.Config,
	rootCA ca.CertificateAuthority,
	intermediateCA ca.CertificateAuthority,
	tpm tpm2.TrustedPlatformModule2,
	authenticator auth.PlatformAuthenticator) PlatformSetup {

	regex, err := regexp.Compile(passwordPolicyPattern)
	if err != nil {
		logger.Fatal(err)
	}

	return &Setup{
		logger:               logger,
		caConfig:             caConfig,
		rootPassword:         rootPassword,
		intermediatePassword: intermediatePassword,
		passwordPolicy:       regex,
		rootCA:               rootCA,
		intermediateCA:       intermediateCA,
		tpm:                  tpm,
		authenticator:        authenticator,
	}
}

// Performs initial platform setup:
// 1. Has the Certificate Authority been initialized?
//   - Yes: Prompt for existing PKCS8 CA password, unseal the CA, start platform
//   - No:  Prompt for new passwork, initialize root and intermediate CAs
func (setup Setup) Setup(password []byte) {

	if !setup.intermediateCA.IsInitialized() {

		setup.printWelcome()

		fmt.Println("")
		fmt.Println("It looks like this is your first time starting the platform...")
		fmt.Println("")
		fmt.Println("Let's take a few minutes to set up a secure and trusted environment.")
		fmt.Println("")
		fmt.Println("Enter a password for the Root Certificate Authority")
		fmt.Println("")

		// Bypass prompts if passwords are configured for auto-unseal
		if setup.rootPassword != nil && setup.intermediatePassword != nil {
			emptyByte := []byte("")
			if !bytes.Equal(setup.rootPassword, emptyByte) &&
				!bytes.Equal(setup.intermediatePassword, emptyByte) {

				setup.initCA(setup.rootPassword, setup.intermediatePassword)
				return
			}
		}

		// Prompt for new passwords
		var rootPass []byte
		for rootPass == nil {
			maybePassword, err := setup.initialPasswordPrompt()
			if err != nil {
				setup.logger.Error(err)
			}
			rootPass = maybePassword
		}

		fmt.Println("\nEnter a password for the Intermediate Certifiate Authority")
		fmt.Println("")
		var intermediatePass []byte
		for intermediatePass == nil {
			maybePassword, err := setup.initialPasswordPrompt()
			if err != nil {
				setup.logger.Error(err)
			}
			intermediatePass = maybePassword
		}

		setup.initCA(rootPass, intermediatePass)
		return
	}

	// Attempt to authenticate the user if a password was supplied
	if len(password) > 0 {
		if err := setup.authenticator.Authenticate(password); err != nil {
			if err == ca.ErrNotInitialized {
				if password != nil {
					setup.initCA(password, password)
					return
				}
			}
			setup.logger.Fatal(err)
		}
	}

	// Abort with error if private key passwords are required in config
	if setup.caConfig.RequirePrivateKeyPassword {
		setup.logger.Fatal(ca.ErrPrivateKeyPasswordRequired)
	}

	// Last attempt to init/load the CA using a blank password
	setup.initCA(password, password)
}

// Reads a password from STDIN
func (setup Setup) PasswordPrompt() []byte {
	setup.printWelcome()
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		setup.logger.Fatal(err)
	}
	return password
}

// Prompt for password with confirmation of the typed password
func (setup Setup) initialPasswordPrompt() ([]byte, error) {

	fmt.Print("Enter Password: ")
	password := setup.readassword()

	fmt.Print("\nConfirm Password: ")
	confirm := setup.readassword()

	if bytes.Compare(password, confirm) != 0 {
		return nil, common.ErrPasswordsDontMatch
	}

	if !setup.passwordPolicy.MatchString(string(password)) {
		setup.logger.Errorf("%s: %s", ca.ErrPasswordComplexity, setup.passwordPolicy)
		return nil, common.ErrPasswordComplexity
	}

	return password, nil
}

// Prints welcome banner
func (setup Setup) printWelcome() {
	color.New(color.FgGreen).Println("Welcome to the Trusted Platform!")
}

// Reads a password from STDIN
func (setup Setup) readassword() []byte {
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		setup.logger.Fatal(err)
	}
	return password
}

// Initialize a Root and Intermediate CA
func (setup Setup) initCA(rootPassword, intermediatePassword []byte) {
	// Initialize the Root CA
	rootPrivKey, rootCert, err := setup.rootCA.Init(
		nil, nil, rootPassword, setup.tpm.RandomReader())
	if err != nil {
		setup.logger.Fatal(err)
	}
	// Initialize the Intermediate CA
	_, _, err = setup.intermediateCA.Init(
		rootPrivKey, rootCert, intermediatePassword, rand.Reader)
	if err != nil {
		setup.logger.Fatal(err)
	}
}
