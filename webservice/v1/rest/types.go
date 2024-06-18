package rest

import (
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/response"
	"github.com/op/go-logging"
)

type RestService interface {
	RegisterEndpoints(router *mux.Router, baseURI, baseFarmURI string) []string
}

type RestServiceRegistry interface {
	JsonWebTokenService() JsonWebTokenServicer
	SystemRestService() SystemRestServicer
}

type GenericRestService[E any] struct {
	logger     *logging.Logger
	jsonWriter response.HttpWriter
	SystemRestService
}
