package rest

import (
	"errors"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

var (
	ErrAuthorizationHeaderRequired = errors.New("authorization header required")
	ErrInvalidToken                = errors.New("invalid token")
	ErrInvalidUserClaim            = errors.New("invalid user id claim")
	ErrInvalidEmailClaim           = errors.New("invalid email claim")
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
