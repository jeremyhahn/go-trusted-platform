package setup

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/pkcs11"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/op/go-logging"
)

type PKCS11 struct {
	appName        string
	logger         *logging.Logger
	caConfig       ca.Config
	pkcs11Config   pkcs11.Config
	rootCA         ca.CertificateAuthority
	intermediateCA ca.CertificateAuthority
	tpm            tpm2.TrustedPlatformModule2
	PlatformSetup
}

func NewPKCS11(
	logger *logging.Logger,
	caConfig ca.Config,
	pkcs11Config pkcs11.Config) PlatformSetup {

	return PKCS11{
		logger:       logger,
		caConfig:     caConfig,
		pkcs11Config: pkcs11Config,
	}
}
