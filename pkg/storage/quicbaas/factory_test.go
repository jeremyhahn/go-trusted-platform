//go:build raft

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
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	dnsEntities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFactory(t *testing.T) (*Factory, func()) {
	t.Helper()

	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	err = factory.Start(context.Background())
	require.NoError(t, err)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		factory.Stop(ctx)
	}

	return factory, cleanup
}

func TestNewFactory_Success(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)
	assert.NotNil(t, factory.Client())
	assert.False(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())
}

func TestNewFactory_InvalidConfig(t *testing.T) {
	cfg := &Config{} // Empty invalid config
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.Error(t, err)
	assert.Nil(t, factory)
}

func TestFactory_StartStop(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	assert.False(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())

	// Start
	err = factory.Start(context.Background())
	require.NoError(t, err)

	assert.True(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())

	// Stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = factory.Stop(ctx)
	cancel()
	require.NoError(t, err)

	assert.True(t, factory.IsClosed())
}

func TestFactory_Stop_Idempotent(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup() // First stop

	// Second stop should be a no-op
	ctx := context.Background()
	err := factory.Stop(ctx)
	require.NoError(t, err)

	// Third stop should also be a no-op
	err = factory.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, factory.IsClosed())
}

// TestFactory_SDK_FollowsLifecycle asserts the factory hands out a working
// SDK client only between Start and Stop.
func TestFactory_SDK_FollowsLifecycle(t *testing.T) {
	factory, err := NewFactory(TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	assert.Nil(t, factory.SDK(), "SDK must be nil before Start")

	require.NoError(t, factory.Start(context.Background()))

	sdk := factory.SDK()
	require.NotNil(t, sdk, "SDK must be available after Start")
	require.NoError(t, sdk.Health().Ping(context.Background()))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, factory.Stop(ctx))

	assert.Nil(t, factory.SDK(), "SDK must be nil after Stop")
}

// TestFactory_Start_AfterStopReturnsErrFactoryClosed asserts a stopped
// factory cannot be restarted.
func TestFactory_Start_AfterStopReturnsErrFactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	err := factory.Start(context.Background())

	var target ErrFactoryClosed
	assert.ErrorAs(t, err, &target)
	assert.False(t, factory.IsStarted())
}

// TestFactory_Start_ServesEveryStorageBackend asserts the embedded factory
// starts and serves KV on each storage backend its test configs select.
func TestFactory_Start_ServesEveryStorageBackend(t *testing.T) {
	tests := []struct {
		name   string
		config func(t TestingT) *Config
	}{
		{name: "Pebble", config: TestConfig},
		{name: "Memory", config: MemoryTestConfig},
		{name: "File", config: FileTestConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factory, err := NewFactory(tc.config(t), logging.DefaultLogger(), nil)
			require.NoError(t, err)
			require.NoError(t, factory.Start(context.Background()))
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				require.NoError(t, factory.Stop(ctx))
			}()

			sdk := factory.SDK()
			require.NotNil(t, sdk)

			ctx := context.Background()
			require.NoError(t, sdk.Health().Ping(ctx))

			data := []byte(`{"backend":"` + tc.name + `"}`)
			put, err := sdk.KV().Put(ctx, &quicbaassdk.PutRequest{
				EntityType: "factory-backend",
				Data:       data,
			})
			require.NoError(t, err)

			got, err := sdk.KV().Get(ctx, &quicbaassdk.GetRequest{
				EntityType: "factory-backend",
				ID:         put.ID,
			})
			require.NoError(t, err)
			assert.True(t, got.Found)
			assert.Equal(t, data, got.Data)
		})
	}
}

func TestFactory_UserDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.UserDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.UserDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_UserDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.UserDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_RegistrationDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.RegistrationDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.RegistrationDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_RegistrationDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.RegistrationDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_RoleDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.RoleDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.RoleDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_RoleDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.RoleDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_WebAuthnDAO_Success(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	dao, err := factory.WebAuthnDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)

	// Second call should return same instance
	dao2, err := factory.WebAuthnDAO()
	require.NoError(t, err)
	assert.Same(t, dao, dao2)
}

func TestFactory_WebAuthnDAO_FactoryClosed(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	cleanup()

	_, err := factory.WebAuthnDAO()
	require.Error(t, err)

	var closedErr ErrFactoryClosed
	assert.ErrorAs(t, err, &closedErr)
}

func TestFactory_SerializerType(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	assert.Equal(t, serializer.SERIALIZER_JSON, factory.SerializerType())
}

func TestFactory_Client(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	client := factory.Client()
	assert.NotNil(t, client)
	assert.True(t, client.IsStarted())
}

func TestFactory_ConcurrentDAOAccess(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	var wg sync.WaitGroup
	errors := make(chan error, 50)

	// Concurrently access all DAOs
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			_, err := factory.UserDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.RegistrationDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.RoleDAO()
			if err != nil {
				errors <- err
			}
		}()

		go func() {
			defer wg.Done()
			_, err := factory.WebAuthnDAO()
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("unexpected error in concurrent access: %v", err)
	}
}

func TestFactory_AllDAOs_Integration(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	// Get all DAOs
	userDAO, err := factory.UserDAO()
	require.NoError(t, err)

	roleDAO, err := factory.RoleDAO()
	require.NoError(t, err)

	regDAO, err := factory.RegistrationDAO()
	require.NoError(t, err)

	webAuthnDAO, err := factory.WebAuthnDAO()
	require.NoError(t, err)

	// Verify they all work
	assert.NotNil(t, userDAO)
	assert.NotNil(t, roleDAO)
	assert.NotNil(t, regDAO)
	assert.NotNil(t, webAuthnDAO)
}

// listPartition lists the stored bytes of every entity of one type the way
// the db dump reads them (pkg/api/daemon DumpEntityType): through the
// factory's client, by the entity type's partition name.
func listPartition(t *testing.T, factory *Factory, entityType string) map[uint64][]byte {
	t.Helper()

	listed, nextToken, err := factory.Client().List(context.Background(), entityType, 100, "", 0)
	require.NoError(t, err)
	require.Empty(t, nextToken, "the %s partition must fit one page", entityType)

	byID := make(map[uint64][]byte, len(listed))
	for _, entity := range listed {
		byID[entity.ID] = entity.Data
	}
	return byID
}

// decodeObject decodes stored entity bytes as the JSON object the db dump
// writes to disk.
func decodeObject(t *testing.T, data []byte) map[string]interface{} {
	t.Helper()

	var object map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &object), "stored entity must be a JSON object")
	return object
}

// TestFactory_DAOSavedEntities_ListedByTypeName asserts that an entity saved
// through a factory DAO is listed under its type name as JSON keyed by the
// entity's json tags, and that each partition holds only its own type.
func TestFactory_DAOSavedEntities_ListedByTypeName(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	ctx := context.Background()

	roleDAO, err := factory.RoleDAO()
	require.NoError(t, err)
	role := &entities.Role{Name: "dump-role"}
	require.NoError(t, roleDAO.Save(ctx, role))
	require.NotZero(t, role.ID)

	userDAO, err := factory.UserDAO()
	require.NoError(t, err)
	user := entities.NewUser("dump@example.com")
	require.NoError(t, userDAO.Save(ctx, user))
	require.NotZero(t, user.ID)

	zoneDAO, err := factory.ZoneDAO()
	require.NoError(t, err)
	zone := &dnsEntities.Zone{
		Name:        "dump.example.com.",
		TTL:         3600,
		Description: "zone for the dump read path",
		RecordSet: dnsEntities.RecordSet{
			ARecords: []*dnsEntities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 300},
				{Name: "api", Value: "192.168.1.2", TTL: 300},
				{Name: "mail", Value: "192.168.1.3", TTL: 300},
			},
		},
	}
	require.NoError(t, zoneDAO.Save(ctx, zone))
	require.NotZero(t, zone.ID)

	roles := listPartition(t, factory, "Role")
	require.Contains(t, roles, role.ID)
	roleObject := decodeObject(t, roles[role.ID])
	assert.Equal(t, "dump-role", roleObject["name"])

	users := listPartition(t, factory, "User")
	require.Contains(t, users, user.ID)
	assert.Equal(t, "dump@example.com", decodeObject(t, users[user.ID])["email"])

	zones := listPartition(t, factory, "Zone")
	require.Len(t, zones, 1, "the Zone partition must hold only the saved zone")
	require.Contains(t, zones, zone.ID)
	zoneObject := decodeObject(t, zones[zone.ID])
	assert.Equal(t, "dump.example.com.", zoneObject["name"])
	assert.Equal(t, float64(3600), zoneObject["ttl"])
	assert.Equal(t, "zone for the dump read path", zoneObject["description"])
	records, ok := zoneObject["records"].(map[string]interface{})
	require.True(t, ok, "zone records must be a JSON object")
	aRecords, ok := records["a"].([]interface{})
	require.True(t, ok, "zone A records must be a JSON array under \"a\"")
	assert.Len(t, aRecords, 3)

	for id, data := range roles {
		assert.NotContains(t, decodeObject(t, data), "records", "Role partition holds a zone at ID %d", id)
	}
}

// TestFactory_DAOSavedZone_GetRoundTrips asserts that the bytes the client
// returns for a DAO-saved zone decode back to the zone that was saved,
// including text that JSON must escape.
func TestFactory_DAOSavedZone_GetRoundTrips(t *testing.T) {
	tests := []struct {
		name string
		zone *dnsEntities.Zone
	}{
		{
			name: "FieldsAndSOA",
			zone: &dnsEntities.Zone{
				Name:        "integrity.example.com.",
				TTL:         7200,
				Description: "data integrity zone",
				Internal:    true,
				RecordSet: dnsEntities.RecordSet{
					SOARecord: dnsEntities.SOARecord{
						Name:       "integrity.example.com.",
						MName:      "ns1.integrity.example.com.",
						RName:      "admin.integrity.example.com.",
						Serial:     2024123102,
						Refresh:    3600,
						Retry:      1800,
						Expire:     604800,
						MinimumTTL: 43200,
						TTL:        7200,
					},
					ARecords: []*dnsEntities.ARecord{
						{Name: "test", Value: "10.0.0.1", TTL: 600},
					},
				},
			},
		},
		{
			name: "SpecialCharacters",
			zone: &dnsEntities.Zone{
				Name:        "special.example.com.",
				TTL:         3600,
				Description: "special chars: \"quotes\", 'apostrophes', <angle>, &ampersand, newline\nhere",
				RecordSet: dnsEntities.RecordSet{
					TXTRecords: []*dnsEntities.TXTRecord{
						{Name: "special.example.com.", Value: "text with spaces and \"quotes\"", TTL: 300},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factory, cleanup := newTestFactory(t)
			defer cleanup()

			ctx := context.Background()
			zoneDAO, err := factory.ZoneDAO()
			require.NoError(t, err)
			require.NoError(t, zoneDAO.Save(ctx, tc.zone))

			data, found, err := factory.Client().Get(ctx, "Zone", tc.zone.ID, 0)
			require.NoError(t, err)
			require.True(t, found)

			var stored dnsEntities.Zone
			require.NoError(t, json.Unmarshal(data, &stored))
			assert.Equal(t, tc.zone.Name, stored.Name)
			assert.Equal(t, tc.zone.TTL, stored.TTL)
			assert.Equal(t, tc.zone.Description, stored.Description)
			assert.Equal(t, tc.zone.Internal, stored.Internal)
			assert.Equal(t, tc.zone.RecordSet.SOARecord, stored.RecordSet.SOARecord)
			assert.Equal(t, tc.zone.RecordSet.ARecords, stored.RecordSet.ARecords)
			assert.Equal(t, tc.zone.RecordSet.TXTRecords, stored.RecordSet.TXTRecords)
		})
	}
}

// TestFactory_List_UnpopulatedTypeIsEmpty asserts that listing a type nothing
// was saved under succeeds with no entities, so the dump skips it.
func TestFactory_List_UnpopulatedTypeIsEmpty(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	assert.Empty(t, listPartition(t, factory, "DeviceProfile"))
}

// TestFactory_List_ReturnsEverySavedRole asserts that one listing page
// returns every DAO-saved role, and keeps doing so under concurrent readers.
func TestFactory_List_ReturnsEverySavedRole(t *testing.T) {
	factory, cleanup := newTestFactory(t)
	defer cleanup()

	ctx := context.Background()
	roleDAO, err := factory.RoleDAO()
	require.NoError(t, err)

	const numRoles = 20
	saved := make([]uint64, 0, numRoles)
	for i := 0; i < numRoles; i++ {
		role := &entities.Role{Name: fmt.Sprintf("bulk-role-%d", i)}
		require.NoError(t, roleDAO.Save(ctx, role))
		saved = append(saved, role.ID)
	}

	roles := listPartition(t, factory, "Role")
	for _, id := range saved {
		assert.Contains(t, roles, id)
	}

	const numReaders = 3
	var wg sync.WaitGroup
	results := make(chan int, numReaders)
	errs := make(chan error, numReaders)
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			listed, _, err := factory.Client().List(ctx, "Role", 100, "", 0)
			if err != nil {
				errs <- err
				return
			}
			results <- len(listed)
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Errorf("concurrent list failed: %v", err)
	}
	for count := range results {
		assert.Equal(t, len(roles), count, "a concurrent reader saw a different Role partition")
	}
}
