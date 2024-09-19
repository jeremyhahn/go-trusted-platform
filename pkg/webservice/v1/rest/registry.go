package rest

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

type RestRegistry struct {
	claimsIssuer        string
	jwtExpiration       int
	logger              *logging.Logger
	jsonWebTokenService JsonWebTokenServicer
	systemRestService   SystemRestServicer
	endpointList        *[]string
	RestServiceRegistry
}

func NewRestServiceRegistry(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes,
	config *config.WebService,
	jwtClaimsIssuer string) RestServiceRegistry {

	endpointList := make([]string, 0)

	httpWriter := response.NewResponseWriter(logger, nil)

	service, err := jwt.NewService(config, ca.Keyring(), serverKeyAttributes)
	if err != nil {
		logger.FatalError(err)
	}

	jsonWebTokenService, err := NewJsonWebTokenRestService(
		logger,
		httpWriter,
		service)
	if err != nil {
		logger.FatalError(err)
	}

	registry := &RestRegistry{
		endpointList:        &endpointList,
		jsonWebTokenService: jsonWebTokenService,
	}

	registry.systemRestService = NewSystemRestService(
		ca,
		serverKeyAttributes,
		httpWriter,
		logger,
		registry.endpointList)

	return registry
}

func (registry *RestRegistry) JsonWebTokenService() JsonWebTokenServicer {
	return registry.jsonWebTokenService
}

func (registry *RestRegistry) SystemRestService() SystemRestServicer {
	return registry.systemRestService
}
