package setup

import (
	"bytes"
	"fmt"
	"regexp"
	"syscall"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/op/go-logging"
	"golang.org/x/term"
)

type PlatformSetup interface {
	Setup() ca.CertificateAuthority
}

type PKCS8 struct {
	appName        string
	logger         *logging.Logger
	passwordPolicy *regexp.Regexp
	caParams       *ca.CAParams
	parentCA       ca.CertificateAuthority
	intermediateCA ca.CertificateAuthority
	tpm            tpm2.TrustedPlatformModule2
}

// Creates a new Platform Setup
func NewPKCS8(
	appName string,
	passwordPolicyPattern string,
	caParams *ca.CAParams,
	parentCA ca.CertificateAuthority,
	intermediateCA ca.CertificateAuthority,
	tpm tpm2.TrustedPlatformModule2) PlatformSetup {

	regex, err := regexp.Compile(passwordPolicyPattern)
	if err != nil {
		caParams.Logger.Fatal(err)
	}

	return &PKCS8{
		appName:        appName,
		logger:         caParams.Logger,
		caParams:       caParams,
		passwordPolicy: regex,
		parentCA:       parentCA,
		intermediateCA: intermediateCA,
		tpm:            tpm,
	}
}

// Performs initial platform setup:
// 1. Has the Certificate Authority been initialized?
//   - Yes: Prompt for CA password, unseal the CA, start platform
//   - No:  Prompt for new passwords, initialize parent and intermediate CAs
func (pkcs8 PKCS8) Setup() ca.CertificateAuthority {

	parentPassword := pkcs8.caParams.Config.Identity[0].KeyPassword
	intermediatePassword := pkcs8.caParams.Config.Identity[pkcs8.caParams.SelectedCA].KeyPassword

	// Bypass prompts if passwords are configured for auto-unseal. This should only
	// be used for development and automating tests
	if parentPassword != "" && intermediatePassword != "" {
		return pkcs8.initCA(parentPassword, intermediatePassword)
	}

	pkcs8.printWelcome()

	fmt.Println("")
	fmt.Println("It looks like this is your first time starting the platform...")
	fmt.Println("")
	fmt.Println("Let's take a few minutes to set up a secure and trusted environment.")
	fmt.Println("")
	fmt.Println("Enter a password for the Root Certificate Authority")
	fmt.Println("")

	// Prompt for new passwords
	var parentPass []byte
	for parentPass == nil {
		password, err := pkcs8.initialPasswordPrompt()
		if err != nil {
			pkcs8.logger.Error(err)
		}
		parentPass = password
	}

	fmt.Println("")
	fmt.Println("\nEnter a password for the Intermediate Certifiate Authority")
	fmt.Println("")
	var intermediatePass []byte
	for intermediatePass == nil {
		password, err := pkcs8.initialPasswordPrompt()
		if err != nil {
			pkcs8.logger.Error(err)
		}
		intermediatePass = password
	}

	// Initialize the CA
	configuredCA := pkcs8.initCA(string(parentPass), string(intermediatePass))

	// Create attestation attributes
	attrs := keystore.X509Attributes{
		CN: configuredCA.Identity().Subject.CommonName,
	}

	// Perform local TPM quote, sign and store to CA blob storage
	if _, _, err := pkcs8.tpm.LocalQuote(attrs, true); err != nil {
		pkcs8.logger.Fatal(err)
	}

	return configuredCA
}

// Prompt for password with confirmation of the typed password
func (pkcs8 PKCS8) initialPasswordPrompt() ([]byte, error) {

	fmt.Print("Enter Password")
	password := pkcs8.readPassword()
	fmt.Println()

	fmt.Println("Confirm Password")
	confirm := pkcs8.readPassword()

	if bytes.Compare(password, confirm) != 0 {
		return nil, common.ErrPasswordsDontMatch
	}

	if !pkcs8.passwordPolicy.MatchString(string(password)) {
		pkcs8.logger.Errorf("%s: %s", common.ErrPasswordComplexity, pkcs8.passwordPolicy)
		return nil, common.ErrPasswordComplexity
	}

	return password, nil
}

// Prints welcome banner
func (pkcs8 PKCS8) printWelcome() {
	color.New(color.FgGreen).Println("Welcome to the Trusted Platform!")
}

// Reads a password from STDIN
func (pkcs8 PKCS8) readPassword() []byte {
	fmt.Printf("%s $ ", pkcs8.appName)
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		pkcs8.logger.Fatal(err)
	}
	return password
}

// Initialize the Certificate Authority/ies. If a Root and Intermediate CA is
// configured in the platform configuration file, then both CA's are initialized
// and the Intermediate is returned as the "Platform CA" that is used for
// all CA operations in the app. The Root CA and keys should then be taken
// offline and stored in a secure physical vault. If only a Root CA is configured,
// (because this is a test or development environment) then only the Root CA
// is initialized and returned.
func (pkcs8 PKCS8) initCA(parentPassword, intermediatePassword string) ca.CertificateAuthority {

	selectedCA := pkcs8.caParams.Config.DefaultCA
	pkcs8.caParams.Config.Identity[0].KeyPassword = parentPassword
	pkcs8.caParams.Config.Identity[selectedCA].KeyPassword = intermediatePassword

	// Initialize the Root CA
	parentCA, err := pkcs8.parentCA.Init(nil)
	if err != nil {
		pkcs8.logger.Fatal(err)
	}

	if pkcs8.intermediateCA != nil {
		// Initialize the Intermediate CA
		_, err = pkcs8.intermediateCA.Init(parentCA)
		if err != nil {
			pkcs8.logger.Fatal(err)
		}
		return pkcs8.intermediateCA
	}
	return pkcs8.parentCA
}
