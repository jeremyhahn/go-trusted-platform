// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

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
