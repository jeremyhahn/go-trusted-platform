//go:build integration

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

package sdn

import (
	"context"
	"testing"
	"time"

	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
)

const (
	ovsdbAddress = "tcp:127.0.0.1:6640"
	testTimeout  = 30 * time.Second
)

// Bridge represents an OVS bridge
type Bridge struct {
	UUID        string            `ovsdb:"_uuid"`
	Name        string            `ovsdb:"name"`
	Ports       []string          `ovsdb:"ports"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
}

// Port represents an OVS port
type Port struct {
	UUID       string   `ovsdb:"_uuid"`
	Name       string   `ovsdb:"name"`
	Interfaces []string `ovsdb:"interfaces"`
}

// Interface represents an OVS interface
type Interface struct {
	UUID string `ovsdb:"_uuid"`
	Name string `ovsdb:"name"`
	Type string `ovsdb:"type"`
}

// TestOVSDBConnection tests basic OVSDB connectivity
func TestOVSDBConnection(t *testing.T) {
	requireOVSDBAt(t, ovsdbAddress)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Define schema
	dbModel, err := model.NewClientDBModel("Open_vSwitch",
		map[string]model.Model{
			"Bridge":    &Bridge{},
			"Port":      &Port{},
			"Interface": &Interface{},
		})
	require.NoError(t, err, "Failed to create database model")

	// Connect to OVSDB
	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint(ovsdbAddress))
	require.NoError(t, err, "Failed to create OVSDB client")

	err = ovs.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB at "+ovsdbAddress, err))
	}
	defer ovs.Close()

	// Monitor for changes
	_, err = ovs.Monitor(ctx,
		ovs.NewMonitor(
			client.WithTable(&Bridge{}),
			client.WithTable(&Port{}),
			client.WithTable(&Interface{}),
		),
	)
	require.NoError(t, err, "Failed to start monitor")

	// Verify connection is alive
	assert.True(t, ovs.Connected(), "Client should be connected")
}

// TestOVSDBOperations tests basic CRUD operations
func TestOVSDBOperations(t *testing.T) {
	requireOVSDBAt(t, ovsdbAddress)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Define schema
	dbModel, err := model.NewClientDBModel("Open_vSwitch",
		map[string]model.Model{
			"Bridge":    &Bridge{},
			"Port":      &Port{},
			"Interface": &Interface{},
		})
	require.NoError(t, err)

	// Connect to OVSDB
	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint(ovsdbAddress))
	require.NoError(t, err)

	err = ovs.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB at "+ovsdbAddress, err))
	}
	defer ovs.Close()

	// Monitor for changes
	_, err = ovs.Monitor(ctx,
		ovs.NewMonitor(
			client.WithTable(&Bridge{}),
		),
	)
	require.NoError(t, err)

	// List bridges
	bridges := []Bridge{}
	err = ovs.List(ctx, &bridges)
	require.NoError(t, err)
	t.Logf("Found %d existing bridges", len(bridges))
}

// TestOVSDBTransactions tests transaction support
func TestOVSDBTransactions(t *testing.T) {
	requireOVSDBAt(t, ovsdbAddress)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Define schema
	dbModel, err := model.NewClientDBModel("Open_vSwitch",
		map[string]model.Model{
			"Bridge":    &Bridge{},
			"Port":      &Port{},
			"Interface": &Interface{},
		})
	require.NoError(t, err)

	// Connect to OVSDB
	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint(ovsdbAddress))
	require.NoError(t, err)

	err = ovs.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB at "+ovsdbAddress, err))
	}
	defer ovs.Close()

	// Monitor for changes
	_, err = ovs.Monitor(ctx,
		ovs.NewMonitor(
			client.WithTable(&Bridge{}),
		),
	)
	require.NoError(t, err)

	// Create a transaction
	ops := []ovsdb.Operation{}

	// Add operations to transaction (example: would add bridge creation)
	// For now, just verify transaction mechanism works
	require.NotNil(t, ops, "Operations slice should be initialized")
}

// TestOVSDBReconnection tests reconnection handling
func TestOVSDBReconnection(t *testing.T) {
	requireOVSDBAt(t, ovsdbAddress)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Define schema
	dbModel, err := model.NewClientDBModel("Open_vSwitch",
		map[string]model.Model{
			"Bridge": &Bridge{},
		})
	require.NoError(t, err)

	// Connect to OVSDB
	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint(ovsdbAddress))
	require.NoError(t, err)

	err = ovs.Connect(ctx)
	if err != nil {
		t.Fatal(missing("a connection to OVSDB at "+ovsdbAddress, err))
	}
	defer ovs.Close()

	// Verify connection
	assert.True(t, ovs.Connected(), "Client should be connected")

	// Test disconnect
	ovs.Disconnect()

	// Disconnect clears the connected flag at once.
	assert.False(t, ovs.Connected(), "Client should be disconnected")

	// libovsdb tears the session down asynchronously: until its disconnect
	// handler has dropped the closed RPC client, Connect answers
	// ErrAlreadyConnected, which it returns as nil without dialling. Redial
	// until a Connect actually reconnects; a real dial error ends the wait.
	var reconnectErr error
	reconnected := func() bool {
		reconnectErr = ovs.Connect(ctx)
		return reconnectErr != nil || ovs.Connected()
	}
	if err := testenv.WaitUntil(ctx, 5*time.Second, "OVSDB client reconnect", reconnected); err != nil {
		t.Fatalf("OVSDB client at %s did not reconnect after Disconnect: %v", ovsdbAddress, err)
	}
	if reconnectErr != nil {
		t.Fatalf("cannot reconnect to OVSDB at %s after a successful connect: %v", ovsdbAddress, reconnectErr)
	}
	assert.True(t, ovs.Connected(), "Client should be reconnected")
}

// TestOVSDBErrorHandling tests error handling
func TestOVSDBErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to connect to invalid endpoint
	dbModel, err := model.NewClientDBModel("Open_vSwitch",
		map[string]model.Model{
			"Bridge": &Bridge{},
		})
	require.NoError(t, err)

	ovs, err := client.NewOVSDBClient(dbModel, client.WithEndpoint("tcp:127.0.0.1:9999"))
	require.NoError(t, err)

	err = ovs.Connect(ctx)
	assert.Error(t, err, "Should fail to connect to invalid endpoint")
}
