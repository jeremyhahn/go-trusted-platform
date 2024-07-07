package rest

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

type RestRegistry struct {
	app                 *app.App
	jsonWebTokenService JsonWebTokenServicer
	systemRestService   SystemRestServicer
	endpointList        *[]string
	RestServiceRegistry
}

func NewRestServiceRegistry(app *app.App) RestServiceRegistry {

	endpointList := make([]string, 0)
	registry := &RestRegistry{
		app:          app,
		endpointList: &endpointList}

	httpWriter := response.NewResponseWriter(app.Logger, nil)

	registry.createJsonWebTokenService()

	registry.systemRestService = NewSystemRestService(
		app,
		httpWriter,
		registry.endpointList)

	return registry
}

func (registry *RestRegistry) JsonWebTokenService() JsonWebTokenServicer {
	return registry.jsonWebTokenService
}

func (registry *RestRegistry) SystemRestService() SystemRestServicer {
	return registry.systemRestService
}

func (registry *RestRegistry) createJsonWebTokenService() {
	httpWriter := response.NewResponseWriter(registry.app.Logger, nil)
	jsonWebTokenService, err := CreateJsonWebTokenService(
		registry.app,
		httpWriter,
		registry.app.WebService.JWTExpiration)
	if err != nil {
		registry.app.Logger.Fatal(err)
	}
	registry.jsonWebTokenService = jsonWebTokenService
}
