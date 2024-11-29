package v1

import (
	"errors"

	"github.com/gorilla/mux"
)

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrInvalidUserClaim  = errors.New("invalid user id claim")
	ErrInvalidEmailClaim = errors.New("invalid email claim")
)

type RestService interface {
	RegisterEndpoints(router *mux.Router, baseURI, baseFarmURI string) []string
}

// type GenericRestService[E any] struct {
// 	logger     *logging.Logger
// 	jsonWriter response.HttpWriter
// 	SystemRestHandler
// }
