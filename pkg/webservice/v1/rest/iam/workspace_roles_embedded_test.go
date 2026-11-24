//go:build raft

package iam_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// newEmbeddedIAMAdapter starts a real embedded QuicBaaS, the transport the
// real-server e2e config runs IAM on, and returns the REST IAM adapter over
// its SDK with one tenant created.
func newEmbeddedIAMAdapter(t *testing.T, tenantID string, maxUsers int32) *iam.QuicBaaSIAMAdapter {
	t.Helper()
	ctx := context.Background()
	f, err := quicbaas.NewFactory(quicbaas.MemoryTestConfig(t), logging.DefaultLogger(), nil)
	if err != nil {
		t.Fatalf("NewFactory: %v", err)
	}
	if err := f.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := f.Stop(stopCtx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	adapter := iam.NewQuicBaaSIAMAdapter(f.SDK().Identity().IAM())
	req := &iam.CreateTenantRequest{ID: tenantID, Name: tenantID}
	if maxUsers > 0 {
		req.Settings = &iam.TenantSettings{MaxUsers: maxUsers}
	}
	if _, err := adapter.CreateTenant(ctx, req); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	return adapter
}

func createEmbeddedUser(t *testing.T, adapter *iam.QuicBaaSIAMAdapter, tenantID, username, email, role string) {
	t.Helper()
	_, err := adapter.CreateUser(context.Background(), tenantID, &iamsdk.CreateUserRequest{
		Username: username,
		Email:    email,
		Roles:    []string{role},
	})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", email, err)
	}
}

// The adapter stores role IDs on the user; the session guards check role
// names. Over the embedded SDK the resolver must answer the names (#2150:
// the e2e admin got 403 "required role not present").
func TestWorkspaceRoleResolverReturnsRoleNamesOverTheEmbeddedSDK(t *testing.T) {
	const tenantID = "workspace-e2e"
	adapter := newEmbeddedIAMAdapter(t, tenantID, 0)
	createEmbeddedUser(t, adapter, tenantID, "admin", "admin@example.com", "admin")

	resolver, err := iam.NewWorkspaceRoleResolver(adapter)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, err := resolver.Roles(context.Background(), tenantID, "admin@example.com")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if !slices.Equal(roles, []string{"admin"}) {
		t.Fatalf("expected the role name [admin], got %v", roles)
	}
}

// The embedded ListUsers only ever reads the first page of users. A user
// beyond it must not be answered "no roles": the resolver fails closed with
// ErrWorkspaceUserListingIncomplete.
func TestWorkspaceRoleResolverRefusesAnIncompleteEmbeddedListing(t *testing.T) {
	const tenantID = "workspace-big"
	adapter := newEmbeddedIAMAdapter(t, tenantID, 1000)
	// "admin" is a system role on every tenant; "member" is not seeded
	// by the embedded store.
	var last string
	for i := 0; i < 101; i++ {
		last = fmt.Sprintf("user-%03d@example.com", i)
		createEmbeddedUser(t, adapter, tenantID, fmt.Sprintf("user-%03d", i), last, "admin")
	}

	resolver, err := iam.NewWorkspaceRoleResolver(adapter)
	if err != nil {
		t.Fatalf("NewWorkspaceRoleResolver: %v", err)
	}
	roles, err := resolver.Roles(context.Background(), tenantID, last)
	if err == nil && slices.Equal(roles, []string{"admin"}) {
		// A complete lookup (the upstream listing fix) is also correct.
		return
	}
	var incomplete iam.ErrWorkspaceUserListingIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected ErrWorkspaceUserListingIncomplete for a user beyond the first page, got roles %v err %v", roles, err)
	}
	if incomplete.TenantID != tenantID {
		t.Fatalf("expected tenant %q in the error, got %q", tenantID, incomplete.TenantID)
	}
	if roles != nil {
		t.Fatalf("an incomplete listing must grant no roles, got %v", roles)
	}
}
