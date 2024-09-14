package rest

import (
	"crypto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/op/go-logging"
)

type RestRegistry struct {
	claimsIssuer        string
	jwtExpiration       int
	logger              *logging.Logger
	jsonWebTokenService JsonWebTokenServicer
	signer              crypto.Signer
	systemRestService   SystemRestServicer
	endpointList        *[]string
	RestServiceRegistry
}

func NewRestServiceRegistry(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes) RestServiceRegistry {

	endpointList := make([]string, 0)
	registry := &RestRegistry{
		endpointList: &endpointList}

	httpWriter := response.NewResponseWriter(logger, nil)

	registry.createJsonWebTokenService(serverKeyAttributes)

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

func (registry *RestRegistry) createJsonWebTokenService(keyAttributes *keystore.KeyAttributes) {
	httpWriter := response.NewResponseWriter(registry.logger, nil)
	// keyfactory, err := registry.app.KeyChainFromConfig(
	// 	registry.app.WebService.Certificate.KeyChainConfig,
	// 	registry.app.PlatformDir,
	// 	// TODO :)
	// 	nil, nil, nil)
	// if err != nil {
	// 	registry.app.Logger.Fatal(err)
	// }
	jsonWebTokenService, err := NewJsonWebTokenService(
		httpWriter,
		registry.jwtExpiration,
		registry.signer,
		registry.claimsIssuer)

	if err != nil {
		registry.logger.Fatal(err)
	}
	registry.jsonWebTokenService = jsonWebTokenService
}
