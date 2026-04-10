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

package service

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

var (
	ErrWebAuthnNotFound = errors.New("service/webauthn: webauthn session data not found")
)

type WebAuthnSessionServicer interface {
	Delete(ctx context.Context, sessionData *entities.Blob) error
	Get(ctx context.Context, id uint64) (*entities.Blob, error)
	Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Blob], error)
	Save(ctx context.Context, sessionData *entities.Blob) error
}

type WebAuthnSessionService struct {
	logger      *logging.Logger
	webAuthnDAO datastore.WebAuthnDAO
	WebAuthnSessionServicer
}

func NewWebAuthnSessionService(
	logger *logging.Logger,
	webAuthnDAO datastore.WebAuthnDAO) WebAuthnSessionServicer {

	return &WebAuthnSessionService{
		logger:      logger,
		webAuthnDAO: webAuthnDAO}
}

func (service *WebAuthnSessionService) Delete(ctx context.Context, sessionData *entities.Blob) error {
	return service.webAuthnDAO.Delete(ctx, sessionData)
}

// Retrieves webauthn session data by it's session id
func (service *WebAuthnSessionService) Get(ctx context.Context, id uint64) (*entities.Blob, error) {
	return service.webAuthnDAO.Get(ctx, id)
}

// Returns a single page of webauthn session data blobs from the database
func (service *WebAuthnSessionService) Page(
	ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Blob], error) {

	return service.webAuthnDAO.Page(ctx, pageQuery)
}

// Saves the provided webauthn session data to the data store
func (service *WebAuthnSessionService) Save(ctx context.Context, sessionData *entities.Blob) error {
	return service.webAuthnDAO.Save(ctx, sessionData)
}
