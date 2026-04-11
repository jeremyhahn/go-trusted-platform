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
	casdk "github.com/jeremyhahn/go-trusted-ca/sdk/go"
)

// Compile-time interface check.
var _ casdk.ACMEStorageFactory = (*Factory)(nil)

// Factory implements casdk.ACMEStorageFactory using QuicBaaS ObjectStorage.
// Each DAO is backed by a genericDAO that maps GenericDAO operations
// onto the ObjectStorage client. Key encoding follows the same namespace
// scheme as the objstore implementation for data compatibility.
type Factory struct {
	storage  objectstorage.Client
	tenantID string
}

// NewFactory creates a new ACME storage factory backed by QuicBaaS ObjectStorage.
func NewFactory(storage objectstorage.Client) (*Factory, error) {
	if storage == nil {
		return nil, NilStorageError{}
	}
	return &Factory{
		storage: storage,
	}, nil
}

// NewTenantFactory creates a new ACME storage factory scoped to a specific tenant.
func NewTenantFactory(storage objectstorage.Client, tenantID string) (*Factory, error) {
	if storage == nil {
		return nil, NilStorageError{}
	}
	return &Factory{
		storage:  storage,
		tenantID: tenantID,
	}, nil
}

// AccountDAO returns a GenericDAO for ACME accounts.
func (f *Factory) AccountDAO() (casdk.GenericDAO[*casdk.ACMEAccountEntity], error) {
	return newGenericDAO[*casdk.ACMEAccountEntity](
		f.storage, "acme/accounts", f.tenantID,
		func() *casdk.ACMEAccountEntity { return &casdk.ACMEAccountEntity{} },
		"account",
	), nil
}

// OrderDAO returns a GenericDAO for ACME orders scoped to a specific account.
func (f *Factory) OrderDAO(accountID uint64) (casdk.GenericDAO[*casdk.ACMEOrderEntity], error) {
	if accountID == 0 {
		return nil, casdk.DAOInvalidEntityIDError{
			EntityType: "order",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*casdk.ACMEOrderEntity](
		f.storage, fmt.Sprintf("acme/orders/%d", accountID), f.tenantID,
		func() *casdk.ACMEOrderEntity { return &casdk.ACMEOrderEntity{} },
		"order",
	), nil
}

// AuthorizationDAO returns a GenericDAO for ACME authorizations scoped to a specific account.
func (f *Factory) AuthorizationDAO(accountID uint64) (casdk.GenericDAO[*casdk.ACMEAuthorizationEntity], error) {
	if accountID == 0 {
		return nil, casdk.DAOInvalidEntityIDError{
			EntityType: "authorization",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*casdk.ACMEAuthorizationEntity](
		f.storage, fmt.Sprintf("acme/authorizations/%d", accountID), f.tenantID,
		func() *casdk.ACMEAuthorizationEntity { return &casdk.ACMEAuthorizationEntity{} },
		"authorization",
	), nil
}

// ChallengeDAO returns a GenericDAO for ACME challenges scoped to a specific account.
func (f *Factory) ChallengeDAO(accountID uint64) (casdk.GenericDAO[*casdk.ACMEChallengeEntity], error) {
	if accountID == 0 {
		return nil, casdk.DAOInvalidEntityIDError{
			EntityType: "challenge",
			Reason:     "account ID must be non-zero",
		}
	}
	return newGenericDAO[*casdk.ACMEChallengeEntity](
		f.storage, fmt.Sprintf("acme/challenges/%d", accountID), f.tenantID,
		func() *casdk.ACMEChallengeEntity { return &casdk.ACMEChallengeEntity{} },
		"challenge",
	), nil
}

// CertificateDAO returns a GenericDAO for ACME certificates.
func (f *Factory) CertificateDAO() (casdk.GenericDAO[*casdk.ACMECertificateEntity], error) {
	return newGenericDAO[*casdk.ACMECertificateEntity](
		f.storage, "acme/certificates", f.tenantID,
		func() *casdk.ACMECertificateEntity { return &casdk.ACMECertificateEntity{} },
		"certificate",
	), nil
}

// NonceDAO returns a GenericDAO for ACME nonces.
func (f *Factory) NonceDAO() (casdk.GenericDAO[*casdk.ACMENonceEntity], error) {
	return newGenericDAO[*casdk.ACMENonceEntity](
		f.storage, "acme/nonces", f.tenantID,
		func() *casdk.ACMENonceEntity { return &casdk.ACMENonceEntity{} },
		"nonce",
	), nil
}

// ExternalAccountBindingDAO returns a GenericDAO for external account bindings.
func (f *Factory) ExternalAccountBindingDAO() (casdk.GenericDAO[*casdk.ACMEExternalAccountBinding], error) {
	return newGenericDAO[*casdk.ACMEExternalAccountBinding](
		f.storage, "acme/eab", f.tenantID,
		func() *casdk.ACMEExternalAccountBinding { return &casdk.ACMEExternalAccountBinding{} },
		"external_account_binding",
	), nil
}
