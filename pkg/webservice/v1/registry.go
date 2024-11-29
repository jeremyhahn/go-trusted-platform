package v1

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/system"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"

	acmehandler "github.com/jeremyhahn/go-trusted-platform/pkg/acme/server/handlers"
	jwthandler "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
)

type RestHandlerRegistry interface {
	ACMERestService() acmehandler.RestServicer
	JSONWebTokenHandler() jwthandler.TokenHandler
	WebAuthnRestService() webauthn.RestHandler
}

type RegistryParams struct {
	ACMEConfig          *acme.Config
	ACMEDAOFactory      dao.Factory
	CA                  ca.CertificateAuthority
	Debug               bool
	HTTPWriter          response.HttpWriter
	Keyring             *platform.Keyring
	JWTAudience         string
	JWTClaimsIssuer     string
	JWTExpiration       int
	Logger              *logging.Logger
	ServerKeyAttributes *keystore.KeyAttributes
	ServiceRegistry     *service.Registry
	TPM                 tpm2.TrustedPlatformModule
	WebServiceConfig    *Config
	WebAuthnConfig      *webauthn.Config
}

type HandlerRegistry struct {
	jwtService *jwt.Service
	params     RegistryParams
	RestHandlerRegistry
}

func NewHandlerRegistry(params RegistryParams) RestHandlerRegistry {
	jwtParams := jwt.ServiceParams{
		Audience:   params.JWTAudience,
		Expiration: params.JWTExpiration,
		Issuer:     params.JWTClaimsIssuer,
		KeyAttrs:   params.ServerKeyAttributes,
		Keyring:    params.Keyring,
	}
	jwtService, err := jwt.NewService(jwtParams)
	if err != nil {
		params.Logger.FatalError(err)
	}
	return &HandlerRegistry{
		jwtService: jwtService,
		params:     params,
	}
}

func (registry *HandlerRegistry) JSONWebTokenHandler() jwthandler.TokenHandler {
	handler, err := jwthandler.NewRestHandler(
		registry.params.Logger,
		registry.params.HTTPWriter,
		registry.jwtService,
		registry.params.ServiceRegistry.UserService())
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}

func (registry *HandlerRegistry) SystemRestService() system.RestHandler {
	return system.NewHandler(
		registry.params.CA,
		registry.params.ServerKeyAttributes,
		registry.params.HTTPWriter,
		registry.params.Logger)
}

func (registry *HandlerRegistry) WebAuthnRestService() webauthn.RestHandler {
	params := webauthn.ServiceParams{
		Config:              registry.params.WebAuthnConfig,
		Debug:               registry.params.Debug,
		JWTService:          registry.jwtService,
		Logger:              registry.params.Logger,
		RegistrationService: registry.params.ServiceRegistry.RegistrationService(),
		ResponseWriter:      registry.params.HTTPWriter,
		SessionService:      registry.params.ServiceRegistry.WebAuthnSessionService(),
		UserService:         registry.params.ServiceRegistry.UserService(),
	}
	handler, err := webauthn.NewHandler(params)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}

func (registry *HandlerRegistry) ACMERestService() acmehandler.RestServicer {
	if registry.params.ACMEConfig.Server == nil {
		registry.params.Logger.Warn("ACME service disabled")
		return nil
	}
	params := &acmehandler.Params{
		ACMEConfig:      registry.params.ACMEConfig,
		CA:              registry.params.CA,
		CN:              registry.params.ServerKeyAttributes.CN,
		DAOFactory:      registry.params.ACMEDAOFactory,
		DeviceService:   registry.params.ServiceRegistry.DeviceService(),
		DNSService:      registry.params.ServiceRegistry.DNSService(),
		Logger:          registry.params.Logger,
		TPM:             registry.params.TPM,
		TLSPort:         registry.params.WebServiceConfig.TLSPort,
		TLSKeyAlgorithm: registry.params.ServerKeyAttributes.KeyAlgorithm,
		TLSStoreType:    registry.params.ServerKeyAttributes.StoreType,
	}
	handler, err := acmehandler.NewRestService(params)
	if err != nil {
		registry.params.Logger.FatalError(err)
	}
	return handler
}
