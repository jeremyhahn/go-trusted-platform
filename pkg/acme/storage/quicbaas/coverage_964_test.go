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
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// objectNotFoundError is the not-found error a QuicBaaS object store
// surfaces for an absent key; the SDK reports it by message, which is
// what isNotFoundErr recognises.
type objectNotFoundError struct {
	Key string
}

func (e objectNotFoundError) Error() string {
	return "object not found: " + e.Key
}

// storeUnavailableError is a transport failure that is not a not-found.
type storeUnavailableError struct{}

func (storeUnavailableError) Error() string {
	return "object store unavailable"
}

// recordingStore is an in-memory object store that records the last request
// of each kind and can fail a chosen operation. Absent keys yield the
// not-found error the real store returns for both GetObject and DeleteObject.
type recordingStore struct {
	*mockObjectStorage
	lastPut    *objectstorage.PutObjectRequest
	lastGet    *objectstorage.GetObjectRequest
	lastDelete *objectstorage.DeleteObjectRequest
	lastList   *objectstorage.ListObjectsRequest
	putErr     error
	getErr     error
	deleteErr  error
	listErr    error
}

func newRecordingStore() *recordingStore {
	return &recordingStore{mockObjectStorage: newMockObjectStorage()}
}

func (s *recordingStore) PutObject(ctx context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	s.lastPut = req
	if s.putErr != nil {
		return nil, s.putErr
	}
	return s.mockObjectStorage.PutObject(ctx, req)
}

func (s *recordingStore) GetObject(ctx context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	s.lastGet = req
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	data, ok := s.objects[req.Key]
	s.mu.RUnlock()
	if !ok {
		return nil, objectNotFoundError{Key: req.Key}
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: data}, nil
}

func (s *recordingStore) DeleteObject(ctx context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	s.lastDelete = req
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.objects[req.Key]; !ok {
		return nil, objectNotFoundError{Key: req.Key}
	}
	delete(s.objects, req.Key)
	return &objectstorage.DeleteObjectResponse{}, nil
}

func (s *recordingStore) ListObjects(ctx context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	s.lastList = req
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.mockObjectStorage.ListObjects(ctx, req)
}

func (s *recordingStore) putRaw(key string, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = value
}

// compoundEntity carries several fields so compound-index lookups can be
// exercised against real field values.
type compoundEntity struct {
	ID     uint64 `json:"id"`
	Status string `json:"status"`
	Region string `json:"region"`
	Serial string `json:"serial"`
}

func (e *compoundEntity) EntityID() uint64      { return e.ID }
func (e *compoundEntity) SetEntityID(id uint64) { e.ID = id }

// unmarshalableEntity cannot be JSON-encoded, so Save must report a
// serialization failure before any write reaches the store.
type unmarshalableEntity struct {
	ID   uint64
	Feed chan int
}

func (e *unmarshalableEntity) EntityID() uint64      { return e.ID }
func (e *unmarshalableEntity) SetEntityID(id uint64) { e.ID = id }

func newCompoundDAO(store objectstorage.Client) *genericDAO[*compoundEntity] {
	return newGenericDAO[*compoundEntity](store, "acme:compound", "tenant-a",
		func() *compoundEntity { return &compoundEntity{} }, "compound")
}

func seedCompound(t *testing.T, d *genericDAO[*compoundEntity]) {
	t.Helper()
	ctx := context.Background()
	for _, e := range []*compoundEntity{
		{ID: 1, Status: "valid", Region: "eu", Serial: "a10"},
		{ID: 2, Status: "valid", Region: "eu", Serial: "b20"},
		{ID: 3, Status: "valid", Region: "us", Serial: "a15"},
		{ID: 4, Status: "revoked", Region: "eu", Serial: "a12"},
	} {
		require.NoError(t, d.Save(ctx, e))
	}
}

func entityIDs(entities []*compoundEntity) []uint64 {
	ids := make([]uint64, 0, len(entities))
	for _, e := range entities {
		ids = append(ids, e.ID)
	}
	return ids
}

func TestCoverage964_SaveIfAbsent_FailsClosed(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)

	stored, err := d.SaveIfAbsent(context.Background(), &compoundEntity{ID: 9})
	assert.False(t, stored)

	var unsupported AtomicWriteUnsupportedError
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, "compound", unsupported.EntityType)
	assert.Contains(t, err.Error(), "compound")
	assert.Contains(t, err.Error(), "SaveIfAbsent")
	assert.Nil(t, store.lastPut, "SaveIfAbsent must not degrade to a plain write")
}

func TestCoverage964_VerifyEntity_SetEntityID(t *testing.T) {
	e := &verifyEntity{}
	e.SetEntityID(42)
	assert.Equal(t, uint64(42), e.EntityID())
}

func TestCoverage964_Save_SendsTenantScopedRequest(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)

	require.NoError(t, d.Save(context.Background(), &compoundEntity{ID: 7, Status: "valid"}))

	require.NotNil(t, store.lastPut)
	assert.Equal(t, "acme:compound/7", store.lastPut.Key)
	assert.Equal(t, "tenant-a", store.lastPut.TenantID)
	assert.Equal(t, defaultTargetBackend, store.lastPut.TargetBackend)
	assert.Equal(t, "application/json", store.lastPut.ContentType)
	assert.Equal(t, map[string]string{"entity_type": "compound", "entity_id": "7"}, store.lastPut.Tags)
}

func TestCoverage964_Save_Errors(t *testing.T) {
	t.Run("zero ID", func(t *testing.T) {
		store := newRecordingStore()
		err := newCompoundDAO(store).Save(context.Background(), &compoundEntity{})
		var invalid trustedca.DAOInvalidEntityIDError
		require.ErrorAs(t, err, &invalid)
		assert.Nil(t, store.lastPut)
	})

	t.Run("serialization failure", func(t *testing.T) {
		store := newRecordingStore()
		d := newGenericDAO[*unmarshalableEntity](store, "acme:bad", "",
			func() *unmarshalableEntity { return &unmarshalableEntity{} }, "bad")
		err := d.Save(context.Background(), &unmarshalableEntity{ID: 1, Feed: make(chan int)})
		var serErr trustedca.DAOSerializationFailedError
		require.ErrorAs(t, err, &serErr)
		assert.Equal(t, "bad", serErr.EntityType)
		assert.Nil(t, store.lastPut)
	})

	t.Run("put failure", func(t *testing.T) {
		store := newRecordingStore()
		store.putErr = storeUnavailableError{}
		err := newCompoundDAO(store).Save(context.Background(), &compoundEntity{ID: 3})
		var opErr StorageOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "put", opErr.Op)
		assert.Equal(t, "acme:compound/3", opErr.Key)
		assert.ErrorIs(t, err, storeUnavailableError{})
	})
}

func TestCoverage964_Get_Errors(t *testing.T) {
	t.Run("absent key is a typed not-found", func(t *testing.T) {
		store := newRecordingStore()
		_, err := newCompoundDAO(store).Get(context.Background(), 5)
		var notFound trustedca.DAONotFoundError
		require.ErrorAs(t, err, &notFound)
		assert.Equal(t, uint64(5), notFound.ID)
		assert.Equal(t, "compound", notFound.EntityType)
		assert.Equal(t, "tenant-a", store.lastGet.TenantID)
	})

	t.Run("store failure", func(t *testing.T) {
		store := newRecordingStore()
		store.getErr = storeUnavailableError{}
		_, err := newCompoundDAO(store).Get(context.Background(), 5)
		var opErr StorageOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "get", opErr.Op)
		assert.Equal(t, "acme:compound/5", opErr.Key)
		assert.False(t, trustedca.IsDAONotFound(err))
	})

	t.Run("corrupt payload", func(t *testing.T) {
		store := newRecordingStore()
		store.putRaw("acme:compound/5", []byte("{not json"))
		_, err := newCompoundDAO(store).Get(context.Background(), 5)
		var desErr trustedca.DAODeserializationFailedError
		require.ErrorAs(t, err, &desErr)
		assert.Equal(t, "compound", desErr.EntityType)
	})
}

func TestCoverage964_Delete(t *testing.T) {
	ctx := context.Background()

	t.Run("removes the stored entity", func(t *testing.T) {
		store := newRecordingStore()
		d := newCompoundDAO(store)
		require.NoError(t, d.Save(ctx, &compoundEntity{ID: 2}))
		require.NoError(t, d.Delete(ctx, &compoundEntity{ID: 2}))
		assert.Equal(t, "tenant-a", store.lastDelete.TenantID)
		_, err := d.Get(ctx, 2)
		assert.True(t, trustedca.IsDAONotFound(err))
	})

	t.Run("absent entity is idempotent", func(t *testing.T) {
		store := newRecordingStore()
		require.NoError(t, newCompoundDAO(store).Delete(ctx, &compoundEntity{ID: 8}))
		assert.Equal(t, "acme:compound/8", store.lastDelete.Key)
	})

	t.Run("zero ID", func(t *testing.T) {
		store := newRecordingStore()
		err := newCompoundDAO(store).Delete(ctx, &compoundEntity{})
		var invalid trustedca.DAOInvalidEntityIDError
		require.ErrorAs(t, err, &invalid)
		assert.Nil(t, store.lastDelete)
	})

	t.Run("store failure", func(t *testing.T) {
		store := newRecordingStore()
		store.deleteErr = storeUnavailableError{}
		err := newCompoundDAO(store).Delete(ctx, &compoundEntity{ID: 8})
		var opErr StorageOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "delete", opErr.Op)
		assert.ErrorIs(t, err, storeUnavailableError{})
	})
}

func TestCoverage964_SaveWithCondition(t *testing.T) {
	ctx := context.Background()

	t.Run("value condition mismatch leaves the entity unchanged", func(t *testing.T) {
		store := newRecordingStore()
		d := newCompoundDAO(store)
		require.NoError(t, d.Save(ctx, &compoundEntity{ID: 1, Status: "pending"}))

		cond := trustedca.DAOCondition{
			Target: trustedca.DAOConditionValue,
			Value:  &compoundEntity{ID: 1, Status: "valid"},
		}
		err := d.SaveWithCondition(ctx, &compoundEntity{ID: 1, Status: "revoked"}, cond)
		var condErr trustedca.DAOConditionFailedError
		require.ErrorAs(t, err, &condErr)

		got, getErr := d.Get(ctx, 1)
		require.NoError(t, getErr)
		assert.Equal(t, "pending", got.Status)
	})

	t.Run("value condition match writes", func(t *testing.T) {
		store := newRecordingStore()
		d := newCompoundDAO(store)
		require.NoError(t, d.Save(ctx, &compoundEntity{ID: 1, Status: "pending"}))

		cond := trustedca.DAOCondition{
			Target: trustedca.DAOConditionValue,
			Value:  &compoundEntity{ID: 1, Status: "pending"},
		}
		require.NoError(t, d.SaveWithCondition(ctx, &compoundEntity{ID: 1, Status: "valid"}, cond))

		got, err := d.Get(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, "valid", got.Status)
	})

	t.Run("store failure on read is returned", func(t *testing.T) {
		store := newRecordingStore()
		store.getErr = storeUnavailableError{}
		err := newCompoundDAO(store).SaveWithCondition(ctx, &compoundEntity{ID: 1}, trustedca.DAOCondition{})
		var opErr StorageOperationError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "get", opErr.Op)
		assert.Nil(t, store.lastPut)
	})
}

func TestCoverage964_QueryByCompoundIndex(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)
	seedCompound(t, d)
	ctx := context.Background()

	tests := []struct {
		name    string
		index   string
		values  []interface{}
		wantIDs []uint64
	}{
		{"both fields match", "Status+Region", []interface{}{"valid", "eu"}, []uint64{1, 2}},
		{"second field narrows", "Status+Region", []interface{}{"valid", "us"}, []uint64{3}},
		{"no match", "Status+Region", []interface{}{"revoked", "us"}, nil},
		{"unknown field matches nothing", "Status+Missing", []interface{}{"valid", "eu"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.QueryByCompoundIndex(ctx, tc.index, tc.values)
			require.NoError(t, err)
			if tc.wantIDs == nil {
				assert.Empty(t, got)
				return
			}
			assert.ElementsMatch(t, tc.wantIDs, entityIDs(got))
		})
	}

	t.Run("value count must equal field count", func(t *testing.T) {
		_, err := d.QueryByCompoundIndex(ctx, "Status+Region", []interface{}{"valid"})
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Error(), "expects 2 fields, got 1 values")
	})
}

func TestCoverage964_ScanByCompoundIndex(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)
	seedCompound(t, d)
	ctx := context.Background()

	tests := []struct {
		name    string
		index   string
		prefix  []interface{}
		start   interface{}
		end     interface{}
		wantIDs []uint64
	}{
		{"range on third field is half-open", "Status+Region+Serial", []interface{}{"valid", "eu"}, "a10", "b20", []uint64{1}},
		{"range covers both", "Status+Region+Serial", []interface{}{"valid", "eu"}, "a", "c", []uint64{1, 2}},
		{"range on second field", "Status+Serial", []interface{}{"valid"}, "a", "b", []uint64{1, 3}},
		{"prefix mismatch excludes", "Status+Serial", []interface{}{"expired"}, "a", "z", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := d.ScanByCompoundIndex(ctx, tc.index, tc.prefix, tc.start, tc.end)
			require.NoError(t, err)
			if tc.wantIDs == nil {
				assert.Empty(t, got)
				return
			}
			assert.ElementsMatch(t, tc.wantIDs, entityIDs(got))
		})
	}

	t.Run("prefix must leave a range field", func(t *testing.T) {
		_, err := d.ScanByCompoundIndex(ctx, "Status+Region", []interface{}{"valid", "eu"}, "a", "z")
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Error(), "prefix values must be fewer than total fields")
	})
}

func TestCoverage964_LoadAll_SkipsForeignAndVanishedKeys(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)
	ctx := context.Background()
	require.NoError(t, d.Save(ctx, &compoundEntity{ID: 1, Status: "valid"}))
	store.putRaw("acme:compound/not-a-number", []byte("{}"))
	store.putRaw("acme:compound/1/child", []byte("{}"))

	got, err := d.QueryByCompoundIndex(ctx, "Status", []interface{}{"valid"})
	require.NoError(t, err)
	assert.Equal(t, []uint64{1}, entityIDs(got))
	assert.Equal(t, "acme:compound/", store.lastList.Prefix)
	assert.Equal(t, "tenant-a", store.lastList.TenantID)
}

func TestCoverage964_LoadAll_PropagatesGetFailure(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)
	ctx := context.Background()
	require.NoError(t, d.Save(ctx, &compoundEntity{ID: 1}))
	store.putRaw("acme:compound/2", []byte("{not json"))

	_, err := d.ScanByCompoundIndex(ctx, "Status+Serial", []interface{}{""}, "", "z")
	var desErr trustedca.DAODeserializationFailedError
	require.ErrorAs(t, err, &desErr)
}

func TestCoverage964_ListFailurePropagates(t *testing.T) {
	ctx := context.Background()
	query := trustedca.DAOPageQuery{PageSize: 10}

	ops := map[string]func(d *genericDAO[*compoundEntity]) error{
		"Count": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.Count(ctx)
			return err
		},
		"Page": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.Page(ctx, query)
			return err
		},
		"ForEachPage": func(d *genericDAO[*compoundEntity]) error {
			return d.ForEachPage(ctx, query, func(trustedca.DAOPageResult[*compoundEntity]) error { return nil })
		},
		"QueryOneByIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.QueryOneByIndex(ctx, "Status", "valid")
			return err
		},
		"ScanByIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.ScanByIndex(ctx, "Serial", "a", "z")
			return err
		},
		"PageByIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.PageByIndex(ctx, "Status", "valid", query)
			return err
		},
		"CountByIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.CountByIndex(ctx, "Status", "valid")
			return err
		},
		"QueryByCompoundIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.QueryByCompoundIndex(ctx, "Status", []interface{}{"valid"})
			return err
		},
		"ScanByCompoundIndex": func(d *genericDAO[*compoundEntity]) error {
			_, err := d.ScanByCompoundIndex(ctx, "Status+Serial", []interface{}{"valid"}, "a", "z")
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			store := newRecordingStore()
			store.listErr = storeUnavailableError{}
			err := op(newCompoundDAO(store))
			var listErr ListOperationError
			require.ErrorAs(t, err, &listErr)
			assert.Equal(t, "compound", listErr.EntityType)
			assert.Equal(t, "acme:compound", listErr.Prefix)
			assert.ErrorIs(t, err, storeUnavailableError{})
		})
	}
}

func TestCoverage964_ForEachPage_CallbackErrorStopsIteration(t *testing.T) {
	store := newRecordingStore()
	d := newCompoundDAO(store)
	seedCompound(t, d)

	calls := 0
	callbackErr := storeUnavailableError{}
	err := d.ForEachPage(context.Background(), trustedca.DAOPageQuery{PageSize: 1},
		func(trustedca.DAOPageResult[*compoundEntity]) error {
			calls++
			return callbackErr
		})
	assert.ErrorIs(t, err, callbackErr)
	assert.Equal(t, 1, calls)
}

// roundTripDAO saves an entity built by the DAO's own entity constructor and
// reads it back, asserting the storage key and tenant the DAO sends.
func roundTripDAO[E trustedca.DAOEntity](t *testing.T, store *recordingStore, dao trustedca.GenericDAO[E], daoErr error, newEntity func() E, wantKey, wantTenant string) {
	t.Helper()
	require.NoError(t, daoErr)
	ctx := context.Background()

	entity := newEntity()
	entity.SetEntityID(5)
	require.NoError(t, dao.Save(ctx, entity))
	assert.Equal(t, wantKey, store.lastPut.Key)
	assert.Equal(t, wantTenant, store.lastPut.TenantID)

	got, err := dao.Get(ctx, 5)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), got.EntityID())
	assert.Equal(t, wantKey, store.lastGet.Key)
	assert.Equal(t, wantTenant, store.lastGet.TenantID)
}

func TestCoverage964_FactoryDAOs_RoundTripUnderTenantKeys(t *testing.T) {
	store := newRecordingStore()
	f, err := NewTenantFactory(store, "t1")
	require.NoError(t, err)

	account := func() *trustedca.ACMEAccountEntity { return &trustedca.ACMEAccountEntity{} }
	order := func() *trustedca.ACMEOrderEntity { return &trustedca.ACMEOrderEntity{} }
	authz := func() *trustedca.ACMEAuthorizationEntity { return &trustedca.ACMEAuthorizationEntity{} }
	challenge := func() *trustedca.ACMEChallengeEntity { return &trustedca.ACMEChallengeEntity{} }
	cert := func() *trustedca.ACMECertificateEntity { return &trustedca.ACMECertificateEntity{} }
	nonce := func() *trustedca.ACMENonceEntity { return &trustedca.ACMENonceEntity{} }
	eab := func() *trustedca.ACMEExternalAccountBinding { return &trustedca.ACMEExternalAccountBinding{} }

	t.Run("Factory", func(t *testing.T) {
		accountDAO, err := f.AccountDAO()
		roundTripDAO(t, store, accountDAO, err, account, "acme:accounts/5", "t1")
		orderDAO, err := f.OrderDAO(3)
		roundTripDAO(t, store, orderDAO, err, order, "acme:orders-3/5", "t1")
		authzDAO, err := f.AuthorizationDAO(3)
		roundTripDAO(t, store, authzDAO, err, authz, "acme:authorizations-3/5", "t1")
		challengeDAO, err := f.ChallengeDAO(3)
		roundTripDAO(t, store, challengeDAO, err, challenge, "acme:challenges-3/5", "t1")
		certDAO, err := f.CertificateDAO()
		roundTripDAO(t, store, certDAO, err, cert, "acme:certificates/5", "t1")
		nonceDAO, err := f.NonceDAO()
		roundTripDAO(t, store, nonceDAO, err, nonce, "acme:nonces/5", "t1")
		eabDAO, err := f.ExternalAccountBindingDAO()
		roundTripDAO(t, store, eabDAO, err, eab, "acme:eab/5", "t1")
	})

	t.Run("ForTenant", func(t *testing.T) {
		taf, err := NewTenantAwareFactory(store)
		require.NoError(t, err)
		scoped, err := taf.ForTenant("t2")
		require.NoError(t, err)

		accountDAO, err := scoped.AccountDAO()
		roundTripDAO(t, store, accountDAO, err, account, "acme/tenants/t2/accounts/5", "t2")
		orderDAO, err := scoped.OrderDAO(3)
		roundTripDAO(t, store, orderDAO, err, order, "acme/tenants/t2/orders/3/5", "t2")
		authzDAO, err := scoped.AuthorizationDAO(3)
		roundTripDAO(t, store, authzDAO, err, authz, "acme/tenants/t2/authorizations/3/5", "t2")
		challengeDAO, err := scoped.ChallengeDAO(3)
		roundTripDAO(t, store, challengeDAO, err, challenge, "acme/tenants/t2/challenges/3/5", "t2")
		certDAO, err := scoped.CertificateDAO()
		roundTripDAO(t, store, certDAO, err, cert, "acme/tenants/t2/certificates/5", "t2")
		nonceDAO, err := scoped.NonceDAO()
		roundTripDAO(t, store, nonceDAO, err, nonce, "acme/tenants/t2/nonces/5", "t2")
		eabDAO, err := scoped.ExternalAccountBindingDAO()
		roundTripDAO(t, store, eabDAO, err, eab, "acme/tenants/t2/eab/5", "t2")
	})
}

func TestCoverage964_IsNotFoundErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed DAO not-found", trustedca.DAONotFoundError{EntityType: "x", ID: 1}, true},
		{"store not-found message", objectNotFoundError{Key: "k"}, true},
		{"not exist message", &MessageError{Msg: "key does not exist"}, true},
		{"no such message", &MessageError{Msg: "no such object"}, true},
		{"other failure", storeUnavailableError{}, false},
		{"wrapped other failure", errors.Join(storeUnavailableError{}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isNotFoundErr(tc.err))
		})
	}
}
