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

package eab

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

const entityTypeEABCredential = "EABCredential"

// DAO defines the interface for EAB credential data access.
type DAO interface {
	datastore.GenericDAO[*EABCredential]

	// FindByKeyID retrieves a credential by its KeyID.
	FindByKeyID(ctx context.Context, keyID string) (*EABCredential, error)

	// FindByProfileID retrieves all credentials for a profile.
	FindByProfileID(ctx context.Context, profileID uint64) ([]*EABCredential, error)

	// FindByTenantID retrieves all credentials for a tenant.
	FindByTenantID(ctx context.Context, tenantID string) ([]*EABCredential, error)

	// FindExpired retrieves all expired credentials.
	FindExpired(ctx context.Context, before time.Time) ([]*EABCredential, error)

	// DeleteExpired removes all expired credentials and returns the count deleted.
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// QuicBaaSDAO provides a QuicBaaS-backed implementation for EAB credential storage.
type QuicBaaSDAO struct {
	*quicbaas.GenericDAO[*EABCredential]
	storage quicbaas.Storage
	logger  *logging.Logger
	shardID uint64
}

// NewQuicBaaSDAO creates a new EAB credential DAO.
func NewQuicBaaSDAO(storage quicbaas.Storage, logger *logging.Logger, opts ...quicbaas.DAOOption) *QuicBaaSDAO {
	genericDAO := quicbaas.NewGenericDAO[*EABCredential](
		storage,
		entityTypeEABCredential,
		func() *EABCredential { return &EABCredential{} },
		logger,
		opts...,
	)
	return &QuicBaaSDAO{
		GenericDAO: genericDAO,
		storage:    storage,
		logger:     logger,
		shardID:    genericDAO.ShardID(),
	}
}

// FindByKeyID retrieves a credential by its KeyID.
func (d *QuicBaaSDAO) FindByKeyID(ctx context.Context, keyID string) (*EABCredential, error) {
	// Try secondary index query first
	results, err := d.storage.Query(ctx, entityTypeEABCredential, "KeyID", []byte(keyID), d.shardID)
	if err != nil {
		return d.findByKeyIDScan(ctx, keyID)
	}

	if len(results) == 0 {
		return d.findByKeyIDScan(ctx, keyID)
	}

	var cred EABCredential
	if err := json.Unmarshal(results[0].Data, &cred); err != nil {
		return nil, quicbaas.ErrDeserializationFailed{EntityType: entityTypeEABCredential, Cause: err}
	}

	return &cred, nil
}

// findByKeyIDScan scans all credentials to find one by KeyID.
func (d *QuicBaaSDAO) findByKeyIDScan(ctx context.Context, keyID string) (*EABCredential, error) {
	var found *EABCredential

	err := d.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 1000}, func(result datastore.PageResult[*EABCredential]) error {
		for _, cred := range result.Entities {
			if cred.KeyID == keyID {
				found = cred
				return datastore.ErrStopIteration
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if found == nil {
		return nil, quicbaas.ErrNotFoundByIndex{EntityType: entityTypeEABCredential, IndexField: "KeyID", Value: keyID}
	}

	return found, nil
}

// FindByProfileID retrieves all credentials for a profile.
func (d *QuicBaaSDAO) FindByProfileID(ctx context.Context, profileID uint64) ([]*EABCredential, error) {
	var credentials []*EABCredential

	err := d.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 1000}, func(result datastore.PageResult[*EABCredential]) error {
		for _, cred := range result.Entities {
			if cred.ProfileID == profileID {
				credentials = append(credentials, cred)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// FindByTenantID retrieves all credentials for a tenant.
func (d *QuicBaaSDAO) FindByTenantID(ctx context.Context, tenantID string) ([]*EABCredential, error) {
	var credentials []*EABCredential

	err := d.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 1000}, func(result datastore.PageResult[*EABCredential]) error {
		for _, cred := range result.Entities {
			if cred.TenantID == tenantID {
				credentials = append(credentials, cred)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// FindExpired retrieves all expired credentials.
func (d *QuicBaaSDAO) FindExpired(ctx context.Context, before time.Time) ([]*EABCredential, error) {
	beforeUnix := before.Unix()
	var credentials []*EABCredential

	err := d.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 1000}, func(result datastore.PageResult[*EABCredential]) error {
		for _, cred := range result.Entities {
			if cred.ExpiresAt > 0 && cred.ExpiresAt < beforeUnix {
				credentials = append(credentials, cred)
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// DeleteExpired removes all expired credentials and returns the count deleted.
func (d *QuicBaaSDAO) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	expired, err := d.FindExpired(ctx, before)
	if err != nil {
		return 0, err
	}

	deleted := 0
	for _, cred := range expired {
		if err := d.Delete(ctx, cred); err != nil {
			d.logger.Warn("Failed to delete expired credential", "id", cred.ID, "error", err)
			continue
		}
		deleted++
	}

	return deleted, nil
}

// Ensure QuicBaaSDAO implements DAO interface.
var _ DAO = (*QuicBaaSDAO)(nil)
