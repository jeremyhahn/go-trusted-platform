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

package device

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// Datastore wraps the underlying storage for devices.
// QuicBaaS is the implicit and only supported backend.
type Datastore struct {
	storage quicbaas.Storage
	logger  *logging.Logger
}

// NewDatastore creates a new Datastore using QuicBaaS storage.
// QuicBaaS is the implicit and only supported backend.
func NewDatastore(storage quicbaas.Storage, logger *logging.Logger) *Datastore {
	return &Datastore{
		storage: storage,
		logger:  logger,
	}
}

// DeviceDAO returns the DeviceDAO for managing devices.
func (ds *Datastore) DeviceDAO() (dao.DeviceDAO, error) {
	return quicbaas.NewDeviceDAO(ds.storage, ds.logger), nil
}

// ProfileDAO returns the DeviceProfileDAO for managing device profiles.
func (ds *Datastore) ProfileDAO() (dao.DeviceProfileDAO, error) {
	return quicbaas.NewDeviceProfileDAO(ds.storage, ds.logger), nil
}

// TemplateDAO returns the DeviceTemplateDAO for managing device templates.
func (ds *Datastore) TemplateDAO() (dao.DeviceTemplateDAO, error) {
	return quicbaas.NewDeviceTemplateDAO(ds.storage, ds.logger), nil
}
