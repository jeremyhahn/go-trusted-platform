package setup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"regexp"
	"syscall"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/op/go-logging"
	"golang.org/x/term"
)

type PlatformSetup interface {
	Setup() []byte
}

type Setup struct {
	appName              string
	logger               *logging.Logger
	passwordPolicy       *regexp.Regexp
	rootPassword         string
	intermediatePassword string
	caConfig             ca.Config
	rootCA               ca.CertificateAuthority
	intermediateCA       ca.CertificateAuthority
	tpm                  tpm2.TrustedPlatformModule2
}

// Creates a new Platform Setup
func NewPlatformSetup(
	appName string,
	logger *logging.Logger,
	passwordPolicyPattern string,
	rootPassword, intermediatePassword string,
	caConfig ca.Config,
	rootCA ca.CertificateAuthority,
	intermediateCA ca.CertificateAuthority,
	tpm tpm2.TrustedPlatformModule2) PlatformSetup {

	regex, err := regexp.Compile(passwordPolicyPattern)
	if err != nil {
		logger.Fatal(err)
	}

	return &Setup{
		appName:              appName,
		logger:               logger,
		caConfig:             caConfig,
		rootPassword:         rootPassword,
		intermediatePassword: intermediatePassword,
		passwordPolicy:       regex,
		rootCA:               rootCA,
		intermediateCA:       intermediateCA,
		tpm:                  tpm,
	}
}

// Performs initial platform setup:
// 1. Has the Certificate Authority been initialized?
//   - Yes: Prompt for CA password, unseal the CA, start platform
//   - No:  Prompt for new passwords, initialize root and intermediate CAs
func (setup Setup) Setup() []byte {

	// Bypass prompts if passwords are configured for auto-unseal. This should only
	// be used for development and automating tests
	if setup.rootPassword != "" && setup.intermediatePassword != "" {
		setup.initCA([]byte(setup.rootPassword), []byte(setup.intermediatePassword))
		return []byte(setup.intermediatePassword)
	}

	setup.printWelcome()

	fmt.Println("")
	fmt.Println("It looks like this is your first time starting the platform...")
	fmt.Println("")
	fmt.Println("Let's take a few minutes to set up a secure and trusted environment.")
	fmt.Println("")
	fmt.Println("Enter a password for the Root Certificate Authority")
	fmt.Println("")

	// Prompt for new passwords
	var rootPass []byte
	for rootPass == nil {
		maybePassword, err := setup.initialPasswordPrompt()
		if err != nil {
			setup.logger.Error(err)
		}
		rootPass = maybePassword
	}

	fmt.Println("")
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

	// Initialize the CA
	setup.initCA(rootPass, intermediatePass)

	// Perform local TPM quote, sign and store to CA blob storage
	if _, err := setup.tpm.LocalQuote(true, intermediatePass); err != nil {
		setup.logger.Fatal(err)
	}

	return intermediatePass
}

// Prompt for password with confirmation of the typed password
func (setup Setup) initialPasswordPrompt() ([]byte, error) {

	fmt.Print("Enter Password")
	password := setup.readPassword()
	fmt.Println()

	fmt.Println("Confirm Password")
	confirm := setup.readPassword()

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
func (setup Setup) readPassword() []byte {
	fmt.Printf("%s $ ", setup.appName)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		setup.logger.Fatal(err)
	}
	return password
}

// Initialize a Root and Intermediate CA
func (setup Setup) initCA(rootPassword, intermediatePassword []byte) {

	setup.rootCA.SetPassword(rootPassword)
	setup.intermediateCA.SetPassword(intermediatePassword)

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
