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

package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeWebAuthn = "WebAuthn"

// WebAuthnDAO provides a key-value store backed implementation of datastore.WebAuthnDAO.
// It stores WebAuthn credentials and session data as binary blobs.
type WebAuthnDAO struct {
	*GenericDAO[*entities.Blob]
}

// NewWebAuthnDAO creates a new WebAuthnDAO.
func NewWebAuthnDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *WebAuthnDAO {
	return &WebAuthnDAO{
		GenericDAO: NewGenericDAO[*entities.Blob](
			storage,
			entityTypeWebAuthn,
			func() *entities.Blob { return &entities.Blob{} },
			logger,
			opts...,
		),
	}
}
