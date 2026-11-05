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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeInvitation = "Invitation"

// InvitationDAO provides a key-value store backed implementation of datastore.InvitationDAO.
type InvitationDAO struct {
	*GenericDAO[*entities.Invitation]
}

// NewInvitationDAO creates a new InvitationDAO.
func NewInvitationDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *InvitationDAO {
	return &InvitationDAO{
		GenericDAO: NewGenericDAO[*entities.Invitation](
			storage,
			entityTypeInvitation,
			func() *entities.Invitation { return &entities.Invitation{} },
			logger,
			opts...,
		),
	}
}

// GetByToken retrieves an invitation by its secure token using a secondary index query.
// If no secondary index exists, falls back to scanning all invitations.
func (d *InvitationDAO) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	results, err := d.storage.Query(ctx, entityTypeInvitation, "Token", []byte(token), d.shardID)
	if err != nil {
		return d.getInvitationByTokenScan(ctx, token)
	}

	if len(results) == 0 {
		return d.getInvitationByTokenScan(ctx, token)
	}

	var invitation entities.Invitation
	if err := datastore.DecodeEntity(results[0].Data, &invitation); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeInvitation, Cause: err}
	}

	return &invitation, nil
}

// getInvitationByTokenScan scans all invitations and finds one by token.
// This is a fallback when secondary index query is not available.
func (d *InvitationDAO) getInvitationByTokenScan(ctx context.Context, token string) (*entities.Invitation, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeInvitation, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var invitation entities.Invitation
			if err := datastore.DecodeEntity(entity.Data, &invitation); err != nil {
				d.logger.Warn("Failed to deserialize invitation", "id", entity.ID, "error", err)
				continue
			}

			if invitation.Token == token {
				return &invitation, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeInvitation, IndexField: "Token", Value: token}
}

// GetByEmail retrieves an invitation by email address using a secondary index query.
// If no secondary index exists, falls back to scanning all invitations.
func (d *InvitationDAO) GetByEmail(ctx context.Context, email string) (*entities.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	results, err := d.storage.Query(ctx, entityTypeInvitation, "Email", []byte(email), d.shardID)
	if err != nil {
		return d.getInvitationByEmailScan(ctx, email)
	}

	if len(results) == 0 {
		return d.getInvitationByEmailScan(ctx, email)
	}

	var invitation entities.Invitation
	if err := datastore.DecodeEntity(results[0].Data, &invitation); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeInvitation, Cause: err}
	}

	return &invitation, nil
}

// getInvitationByEmailScan scans all invitations and finds one by email.
// This is a fallback when secondary index query is not available.
func (d *InvitationDAO) getInvitationByEmailScan(ctx context.Context, email string) (*entities.Invitation, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeInvitation, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var invitation entities.Invitation
			if err := datastore.DecodeEntity(entity.Data, &invitation); err != nil {
				d.logger.Warn("Failed to deserialize invitation", "id", entity.ID, "error", err)
				continue
			}

			if invitation.Email == email {
				return &invitation, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeInvitation, IndexField: "Email", Value: email}
}

// GetByTenant retrieves all invitations for a tenant.
// This scans all invitations and filters by TenantID.
func (d *InvitationDAO) GetByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var invitations []*entities.Invitation
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeInvitation, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var invitation entities.Invitation
			if err := datastore.DecodeEntity(entity.Data, &invitation); err != nil {
				d.logger.Warn("Failed to deserialize invitation", "id", entity.ID, "error", err)
				continue
			}

			if invitation.TenantID == tenantID {
				invitations = append(invitations, &invitation)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return invitations, nil
}

// GetPendingByTenant retrieves all pending invitations for a tenant.
// This scans all invitations and filters by TenantID AND Status=="pending".
func (d *InvitationDAO) GetPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var invitations []*entities.Invitation
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeInvitation, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var invitation entities.Invitation
			if err := datastore.DecodeEntity(entity.Data, &invitation); err != nil {
				d.logger.Warn("Failed to deserialize invitation", "id", entity.ID, "error", err)
				continue
			}

			if invitation.TenantID == tenantID && invitation.Status == entities.InvitationStatusPending {
				invitations = append(invitations, &invitation)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return invitations, nil
}
