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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// DefaultService provides the default implementation of the EAB Service interface.
type DefaultService struct {
	dao    DAO
	logger *logging.Logger
}

// NewService creates a new EAB credential service.
func NewService(dao DAO, logger *logging.Logger) *DefaultService {
	return &DefaultService{
		dao:    dao,
		logger: logger,
	}
}

// Generate creates a new EAB credential for a device profile.
func (s *DefaultService) Generate(ctx context.Context, params GenerateParams) (*Credential, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	keyLen := params.HMACKeyLen
	if keyLen == 0 {
		keyLen = DefaultHMACKeyLength
	}

	hmacKey := make([]byte, keyLen)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, ErrKeyGenerationFailed{Cause: err}
	}

	keyIDBytes := make([]byte, 16)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, ErrKeyGenerationFailed{Cause: err}
	}
	keyID := base64.RawURLEncoding.EncodeToString(keyIDBytes)

	now := time.Now()
	expiresAt := time.Time{}
	if params.ExpiresIn > 0 {
		expiresAt = now.Add(params.ExpiresIn)
	}

	entity := &EABCredential{
		KeyID:     keyID,
		HMACKey:   hmacKey,
		ProfileID: params.ProfileID,
		TenantID:  params.TenantID,
		Status:    uint8(StatusActive),
		CreatedAt: now.Unix(),
	}
	if !expiresAt.IsZero() {
		entity.ExpiresAt = expiresAt.Unix()
	}

	if err := s.dao.Save(ctx, entity); err != nil {
		return nil, err
	}

	return entityToCredential(entity), nil
}

// Get retrieves an EAB credential by its ID.
func (s *DefaultService) Get(ctx context.Context, id uint64) (*Credential, error) {
	if id == 0 {
		return nil, ErrInvalidCredential{Reason: "id cannot be zero"}
	}

	entity, err := s.dao.Get(ctx, id)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if errors.As(err, &notFound) {
			return nil, ErrCredentialNotFound{ID: id}
		}
		return nil, err
	}

	return entityToCredential(entity), nil
}

// GetByKeyID retrieves an EAB credential by its KeyID.
func (s *DefaultService) GetByKeyID(ctx context.Context, keyID string) (*Credential, error) {
	if keyID == "" {
		return nil, ErrInvalidCredential{Reason: "keyID cannot be empty"}
	}

	entity, err := s.dao.FindByKeyID(ctx, keyID)
	if err != nil {
		var notFound quicbaas.ErrNotFoundByIndex
		if errors.As(err, &notFound) {
			return nil, ErrCredentialNotFound{KeyID: keyID}
		}
		return nil, err
	}

	return entityToCredential(entity), nil
}

// Revoke marks a credential as revoked.
func (s *DefaultService) Revoke(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrInvalidCredential{Reason: "id cannot be zero"}
	}

	entity, err := s.dao.Get(ctx, id)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if errors.As(err, &notFound) {
			return ErrCredentialNotFound{ID: id}
		}
		return err
	}

	entity.Status = uint8(StatusRevoked)
	return s.dao.Save(ctx, entity)
}

// MarkUsed marks a credential as used after successful enrollment.
func (s *DefaultService) MarkUsed(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrInvalidCredential{Reason: "id cannot be zero"}
	}

	entity, err := s.dao.Get(ctx, id)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if errors.As(err, &notFound) {
			return ErrCredentialNotFound{ID: id}
		}
		return err
	}

	entity.Status = uint8(StatusUsed)
	entity.UsedAt = time.Now().Unix()
	return s.dao.Save(ctx, entity)
}

// Validate checks if a credential is valid for use.
func (s *DefaultService) Validate(ctx context.Context, keyID string, hmacKey []byte) (*Credential, error) {
	if keyID == "" {
		return nil, ErrInvalidCredential{Reason: "keyID cannot be empty"}
	}
	if len(hmacKey) == 0 {
		return nil, ErrInvalidCredential{Reason: "hmacKey cannot be empty"}
	}

	entity, err := s.dao.FindByKeyID(ctx, keyID)
	if err != nil {
		var notFound quicbaas.ErrNotFoundByIndex
		if errors.As(err, &notFound) {
			return nil, ErrCredentialNotFound{KeyID: keyID}
		}
		return nil, err
	}

	if subtle.ConstantTimeCompare(entity.HMACKey, hmacKey) != 1 {
		return nil, ErrInvalidCredential{Reason: "HMAC key mismatch"}
	}

	cred := entityToCredential(entity)

	switch Status(entity.Status) {
	case StatusRevoked:
		return nil, ErrCredentialRevoked{ID: entity.ID, KeyID: keyID}
	case StatusExpired:
		return nil, ErrCredentialExpired{ID: entity.ID, KeyID: keyID}
	case StatusUsed:
		return nil, ErrCredentialAlreadyUsed{ID: entity.ID, KeyID: keyID}
	}

	if cred.IsExpired() {
		entity.Status = uint8(StatusExpired)
		saveErr := s.dao.Save(ctx, entity)
		if saveErr != nil {
			s.logger.Warn("Failed to update expired credential status", "id", entity.ID, "error", saveErr)
		}
		return nil, ErrCredentialExpired{ID: entity.ID, KeyID: keyID}
	}

	return cred, nil
}

// ListByProfile retrieves all credentials for a given profile ID.
func (s *DefaultService) ListByProfile(ctx context.Context, profileID uint64) ([]*Credential, error) {
	if profileID == 0 {
		return nil, ErrInvalidProfileID{ProfileID: profileID}
	}

	entities, err := s.dao.FindByProfileID(ctx, profileID)
	if err != nil {
		return nil, err
	}

	credentials := make([]*Credential, len(entities))
	for i, e := range entities {
		credentials[i] = entityToCredential(e)
	}

	return credentials, nil
}

// ListByTenant retrieves all credentials for a given tenant ID.
func (s *DefaultService) ListByTenant(ctx context.Context, tenantID string) ([]*Credential, error) {
	if tenantID == "" {
		return nil, ErrInvalidTenantID{TenantID: tenantID}
	}

	entities, err := s.dao.FindByTenantID(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	credentials := make([]*Credential, len(entities))
	for i, e := range entities {
		credentials[i] = entityToCredential(e)
	}

	return credentials, nil
}

// CleanupExpired removes all expired credentials.
func (s *DefaultService) CleanupExpired(ctx context.Context) (int, error) {
	return s.dao.DeleteExpired(ctx, time.Now())
}

// Delete removes a credential by ID.
func (s *DefaultService) Delete(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrInvalidCredential{Reason: "id cannot be zero"}
	}

	entity, err := s.dao.Get(ctx, id)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if errors.As(err, &notFound) {
			return ErrCredentialNotFound{ID: id}
		}
		return err
	}

	return s.dao.Delete(ctx, entity)
}

// Count returns the total number of credentials.
func (s *DefaultService) Count(ctx context.Context) (int, error) {
	return s.dao.Count(ctx)
}

// Page retrieves a paginated list of credentials.
func (s *DefaultService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*Credential], error) {
	entityResult, err := s.dao.Page(ctx, query)
	if err != nil {
		return datastore.PageResult[*Credential]{}, err
	}

	credentials := make([]*Credential, len(entityResult.Entities))
	for i, e := range entityResult.Entities {
		credentials[i] = entityToCredential(e)
	}

	return datastore.PageResult[*Credential]{
		Entities: credentials,
		Page:     entityResult.Page,
		PageSize: entityResult.PageSize,
		Total:    entityResult.Total,
		HasMore:  entityResult.HasMore,
	}, nil
}

// entityToCredential converts a storage entity to a domain credential.
func entityToCredential(e *EABCredential) *Credential {
	cred := &Credential{
		ID:        e.ID,
		KeyID:     e.KeyID,
		HMACKey:   e.HMACKey,
		ProfileID: e.ProfileID,
		TenantID:  e.TenantID,
		Status:    Status(e.Status),
		CreatedAt: time.Unix(e.CreatedAt, 0),
	}
	if e.ExpiresAt > 0 {
		cred.ExpiresAt = time.Unix(e.ExpiresAt, 0)
	}
	if e.UsedAt > 0 {
		cred.UsedAt = time.Unix(e.UsedAt, 0)
	}
	return cred
}

// Ensure DefaultService implements Service interface.
var _ Service = (*DefaultService)(nil)
