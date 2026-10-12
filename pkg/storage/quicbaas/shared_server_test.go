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
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genericTestEntityType is the entity type the GenericDAO tests store under.
const genericTestEntityType = "TestRole"

// sharedServerEntityTypes are the entity types the DAO tests write on the
// shared server. newSharedTestClient deletes every entity of these types
// before a test starts, which is what makes one server per package equivalent
// to the server per test it replaces (#208): a freshly booted server holds
// none of them (TestSharedServer_FreshServerHoldsNoTestEntities).
var sharedServerEntityTypes = []string{
	genericTestEntityType,
	entityTypeRole,
	entityTypeUser,
	entityTypeRegistration,
	entityTypeWebAuthn,
}

// sharedServer is the package's single embedded server for the DAO tests.
// It boots on first use, not in TestMain, so a -run that selects none of
// those tests pays nothing; TestMain stops it once every test has run.
var sharedServer struct {
	once   sync.Once
	dir    string
	config *Config
	server *EmbeddedServer
	err    error
}

// tempDirT satisfies TestingT for a directory that outlives any one test, so
// the shared server is built from the same TestConfig the per-test servers use.
type tempDirT struct {
	dir string
}

func (d tempDirT) TempDir() string { return d.dir }
func (tempDirT) Name() string      { return "shared-embedded-server" }
func (tempDirT) Helper()           {}

func TestMain(m *testing.M) {
	code := m.Run()
	stopSharedServer()
	os.Exit(code)
}

// bootSharedServer starts the shared embedded server in a fresh directory.
func bootSharedServer() error {
	dir, err := os.MkdirTemp("", "quicbaas-shared-server-")
	if err != nil {
		return err
	}
	sharedServer.dir = dir

	cfg := TestConfig(tempDirT{dir: dir})
	server, err := NewEmbeddedServer(cfg, logging.DefaultLogger())
	if err != nil {
		return err
	}
	// context.Background(), deliberately (#270): Start runs first boot
	// synchronously, so a deadline here could only report a slow but
	// successful boot as a failure. go test -timeout is the hang backstop.
	if err := server.Start(context.Background()); err != nil {
		return err
	}

	sharedServer.config = cfg
	sharedServer.server = server
	return nil
}

// stopSharedServer stops the shared server, if it was booted, and removes
// its directory. It reports failures on stderr: TestMain has no test to fail.
func stopSharedServer() {
	if sharedServer.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := sharedServer.server.Stop(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "shared embedded server stop: %v\n", err)
		}
	}
	if sharedServer.dir != "" {
		if err := os.RemoveAll(sharedServer.dir); err != nil {
			fmt.Fprintf(os.Stderr, "shared embedded server cleanup: %v\n", err)
		}
	}
}

// newSharedTestClient returns a started client on the shared embedded server,
// with every entity of sharedServerEntityTypes deleted. The client stops when
// the test ends; the server keeps running for the next test. Tests using it
// must not call t.Parallel: the wipe assumes one test owns the server.
func newSharedTestClient(t *testing.T) *Client {
	t.Helper()

	sharedServer.once.Do(func() { sharedServer.err = bootSharedServer() })
	require.NoError(t, sharedServer.err, "failed to start the shared embedded server")

	logger := logging.DefaultLogger()
	client, err := NewClient(sharedServer.config, logger)
	require.NoError(t, err, "failed to create client")
	err = client.StartWithService(context.Background(), sharedServer.server.Service())
	require.NoError(t, err, "failed to start client with service")
	t.Cleanup(func() {
		if err := client.Stop(context.Background()); err != nil {
			t.Logf("client stop error: %v", err)
		}
	})

	err = deleteAllEntities(context.Background(), client, sharedServerEntityTypes)
	require.NoError(t, err, "failed to reset the shared embedded server")
	return client
}

// deleteAllEntities deletes every entity of the given types. It lists from
// the start after each batch rather than following page tokens, which the
// deletions would invalidate.
func deleteAllEntities(ctx context.Context, storage Storage, entityTypes []string) error {
	for _, entityType := range entityTypes {
		for {
			batch, _, err := storage.List(ctx, entityType, 1000, "", 0)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				break
			}
			for _, entity := range batch {
				if err := storage.Delete(ctx, entityType, entity.ID, 0); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// countEntities returns how many entities of entityType the storage holds.
func countEntities(t *testing.T, storage Storage, entityType string) int {
	t.Helper()
	batch, _, err := storage.List(context.Background(), entityType, 1000, "", 0)
	require.NoError(t, err)
	return len(batch)
}

// The wipe in newSharedTestClient only reproduces a fresh server if a fresh
// server holds none of the wiped entity types. If first boot ever starts
// seeding one of them, this fails rather than the wipe silently deleting it.
func TestSharedServer_FreshServerHoldsNoTestEntities(t *testing.T) {
	setup := newTestClient(t)
	defer setup.cleanup()

	for _, entityType := range sharedServerEntityTypes {
		assert.Zero(t, countEntities(t, setup.client, entityType),
			"a fresh embedded server holds %s entities", entityType)
	}
}

// What one test leaves on the shared server, the next one must not see.
func TestNewSharedTestClient_StartsFromEmptyServer(t *testing.T) {
	first := newSharedTestClient(t)
	ctx := context.Background()
	for _, entityType := range sharedServerEntityTypes {
		dao := NewGenericDAO[*entities.Role](first, entityType,
			func() *entities.Role { return &entities.Role{} }, logging.DefaultLogger())
		for i := 0; i < 3; i++ {
			require.NoError(t, dao.Save(ctx, &entities.Role{Name: fmt.Sprintf("leftover-%d", i)}))
		}
		require.Equal(t, 3, countEntities(t, first, entityType))
	}

	second := newSharedTestClient(t)
	for _, entityType := range sharedServerEntityTypes {
		assert.Zero(t, countEntities(t, second, entityType),
			"%s entities from an earlier test survived the reset", entityType)
	}
}

func TestDeleteAllEntities_SpansMoreThanOneListBatch(t *testing.T) {
	client := newSharedTestClient(t)
	ctx := context.Background()
	dao := NewGenericDAO[*entities.Role](client, genericTestEntityType,
		func() *entities.Role { return &entities.Role{} }, logging.DefaultLogger())
	for i := 0; i < 1001; i++ {
		require.NoError(t, dao.Save(ctx, &entities.Role{Name: fmt.Sprintf("role-%d", i)}))
	}

	require.NoError(t, deleteAllEntities(ctx, client, []string{genericTestEntityType}))
	assert.Zero(t, countEntities(t, client, genericTestEntityType))
}

func TestDeleteAllEntities_StoppedClient(t *testing.T) {
	client := newSharedTestClient(t)
	require.NoError(t, client.Stop(context.Background()))

	err := deleteAllEntities(context.Background(), client, sharedServerEntityTypes)

	var notStarted ErrServerNotStarted
	assert.ErrorAs(t, err, &notStarted)
}
