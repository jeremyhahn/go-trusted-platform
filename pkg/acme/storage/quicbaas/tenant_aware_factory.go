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

package quicbaas

import (
	"fmt"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

// Compile-time interface check.
var _ trustedca.ACMETenantAwareFactory = (*TenantAwareFactory)(nil)

// TenantAwareFactory extends Factory with tenant-scoped DAO creation.
// It implements the trustedca.ACMETenantAwareFactory interface using QuicBaaS
// ObjectStorage, providing tenant data isolation via the TenantID field on
// every ObjectStorage request.
type TenantAwareFactory struct {
	Factory
}

// NewTenantAwareFactory creates a new tenant-aware ACME storage factory backed
// by QuicBaaS ObjectStorage.
func NewTenantAwareFactory(storage objectstorage.Client) (*TenantAwareFactory, error) {
	if storage == nil {
		return nil, NilStorageError{}
	}
	return &TenantAwareFactory{
		Factory: Factory{
			storage: storage,
		},
	}, nil
}

// TenantDAO returns a GenericDAO for managing tenants.
// This DAO is platform-scoped (no tenant prefix) and is intended for
// super-admin operations only.
func (f *TenantAwareFactory) TenantDAO() (trustedca.GenericDAO[*trustedca.ACMETenant], error) {
	return newGenericDAO[*trustedca.ACMETenant](
		f.storage, "acme/tenants", "",
		func() *trustedca.ACMETenant { return &trustedca.ACMETenant{} },
		"tenant",
	), nil
}

// ForTenant returns a tenant-scoped Factory. All DAOs created by the returned
// factory set TenantID on every ObjectStorage request, ensuring data isolation.
func (f *TenantAwareFactory) ForTenant(tenantID string) (trustedca.ACMEStorageFactory, error) {
	if tenantID == "" {
		return nil, InvalidTenantIDError{}
	}
	return &tenantScopedFactory{
		storage:  f.storage,
		tenantID: tenantID,
	}, nil
}

// GetTenantID returns the current tenant ID. Returns empty string for the
// platform-scoped TenantAwareFactory.
func (f *TenantAwareFactory) GetTenantID() string {
	return f.tenantID
}

// tenantScopedFactory is a Factory that sets the TenantID on every
// ObjectStorage request for data isolation. It uses key prefixes under
// the tenant namespace: "acme/tenants/{tenantID}/{collection}/{entityID}".
type tenantScopedFactory struct {
	storage  objectstorage.Client
	tenantID string
}

func (f *tenantScopedFactory) prefix(base string) string {
	return fmt.Sprintf("acme/tenants/%s/%s", f.tenantID, base)
}

// AccountDAO returns a tenant-scoped GenericDAO for ACME accounts.
func (f *tenantScopedFactory) AccountDAO() (trustedca.GenericDAO[*trustedca.ACMEAccountEntity], error) {
	return newGenericDAO[*trustedca.ACMEAccountEntity](
		f.storage, f.prefix("accounts"), f.tenantID,
		func() *trustedca.ACMEAccountEntity { return &trustedca.ACMEAccountEntity{} },
		"account",
	), nil
}

// OrderDAO returns a tenant-scoped GenericDAO for ACME orders.
func (f *tenantScopedFactory) OrderDAO(accountID uint64) (trustedca.GenericDAO[*trustedca.ACMEOrderEntity], error) {
	if accountID == 0 {
		return nil, trustedca.DAOInvalidEntityIDError{
			EntityType: "order",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*trustedca.ACMEOrderEntity](
		f.storage, f.prefix(fmt.Sprintf("orders/%d", accountID)), f.tenantID,
		func() *trustedca.ACMEOrderEntity { return &trustedca.ACMEOrderEntity{} },
		"order",
	), nil
}

// AuthorizationDAO returns a tenant-scoped GenericDAO for ACME authorizations.
func (f *tenantScopedFactory) AuthorizationDAO(accountID uint64) (trustedca.GenericDAO[*trustedca.ACMEAuthorizationEntity], error) {
	if accountID == 0 {
		return nil, trustedca.DAOInvalidEntityIDError{
			EntityType: "authorization",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*trustedca.ACMEAuthorizationEntity](
		f.storage, f.prefix(fmt.Sprintf("authorizations/%d", accountID)), f.tenantID,
		func() *trustedca.ACMEAuthorizationEntity { return &trustedca.ACMEAuthorizationEntity{} },
		"authorization",
	), nil
}

// ChallengeDAO returns a tenant-scoped GenericDAO for ACME challenges.
func (f *tenantScopedFactory) ChallengeDAO(accountID uint64) (trustedca.GenericDAO[*trustedca.ACMEChallengeEntity], error) {
	if accountID == 0 {
		return nil, trustedca.DAOInvalidEntityIDError{
			EntityType: "challenge",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*trustedca.ACMEChallengeEntity](
		f.storage, f.prefix(fmt.Sprintf("challenges/%d", accountID)), f.tenantID,
		func() *trustedca.ACMEChallengeEntity { return &trustedca.ACMEChallengeEntity{} },
		"challenge",
	), nil
}

// CertificateDAO returns a tenant-scoped GenericDAO for ACME certificates.
func (f *tenantScopedFactory) CertificateDAO() (trustedca.GenericDAO[*trustedca.ACMECertificateEntity], error) {
	return newGenericDAO[*trustedca.ACMECertificateEntity](
		f.storage, f.prefix("certificates"), f.tenantID,
		func() *trustedca.ACMECertificateEntity { return &trustedca.ACMECertificateEntity{} },
		"certificate",
	), nil
}

// NonceDAO returns a tenant-scoped GenericDAO for ACME nonces.
func (f *tenantScopedFactory) NonceDAO() (trustedca.GenericDAO[*trustedca.ACMENonceEntity], error) {
	return newGenericDAO[*trustedca.ACMENonceEntity](
		f.storage, f.prefix("nonces"), f.tenantID,
		func() *trustedca.ACMENonceEntity { return &trustedca.ACMENonceEntity{} },
		"nonce",
	), nil
}

// ExternalAccountBindingDAO returns a tenant-scoped GenericDAO for external account bindings.
func (f *tenantScopedFactory) ExternalAccountBindingDAO() (trustedca.GenericDAO[*trustedca.ACMEExternalAccountBinding], error) {
	return newGenericDAO[*trustedca.ACMEExternalAccountBinding](
		f.storage, f.prefix("eab"), f.tenantID,
		func() *trustedca.ACMEExternalAccountBinding { return &trustedca.ACMEExternalAccountBinding{} },
		"external_account_binding",
	), nil
}
