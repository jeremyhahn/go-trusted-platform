package auth

import (
	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/op/go-logging"
)

const (
	infoInsecureRootPassword     = "authenticator/pkcs8: using INSECURE Root CA password"
	insecureIntermediatePassword = "authenticator/pkcs8: using INSECURE Intermediate CA password"
)

type PlatformAuthenticator interface {
	Authenticate(password []byte) error
	Provision(cn string, password, caPassword []byte) error
}

type PKCS8Authenticator struct {
	logger               *logging.Logger
	ca                   ca.CertificateAuthority
	rootPassword         []byte
	intermediatePassword []byte
	PlatformAuthenticator
}

func NewPKCS8Authenticator(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	rootPassword, intermediatePassword []byte) PlatformAuthenticator {

	return PKCS8Authenticator{
		logger:               logger,
		ca:                   ca,
		rootPassword:         rootPassword,
		intermediatePassword: intermediatePassword,
	}
}

// Authenticates a Certificate Authority PKCS8 private key password
func (authenticator PKCS8Authenticator) Authenticate(password []byte) error {
	if !authenticator.ca.IsInitialized() {
		return ca.ErrNotInitialized
	}
	// If the rootPassword or intermediatePassword is set,
	// emit a log warning and use them to transparently log
	// into the platform without prompting for a password.
	if authenticator.rootPassword != nil {
		authenticator.warn(infoInsecureRootPassword)
		_, err := authenticator.ca.CAPrivKey([]byte(authenticator.rootPassword))
		if err != nil {
			return err
		}
	} else if authenticator.intermediatePassword != nil {
		authenticator.warn(insecureIntermediatePassword)
		_, err := authenticator.ca.CAPrivKey([]byte(authenticator.intermediatePassword))
		if err != nil {
			return err
		}
	} else {
		// Authenticate the user-provided password
		if _, err := authenticator.ca.CAPrivKey(password); err != nil {
			return err
		}
	}
	return nil
}

// Creates a new public / private key
func (authenticator PKCS8Authenticator) Provision(cn string, password, caPassword []byte) error {
	if authenticator.rootPassword != nil {
		_, err := authenticator.ca.CAPrivKey([]byte(authenticator.rootPassword))
		if err != nil {
			return err
		}
	} else if authenticator.intermediatePassword != nil {
		_, err := authenticator.ca.CAPrivKey([]byte(authenticator.intermediatePassword))
		if err != nil {
			return err
		}
	}
	return nil
}

func (authenticator PKCS8Authenticator) warn(message string) {
	color.New(color.FgYellow).Println(message)
}
