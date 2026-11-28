package daemon

import (
	"context"
	"testing"

	quiciam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser/iamusertest"
)

// TestIAMCertificatePrincipals_DeviceReadStaysRefusedUntilTheVocabularyIsDeclaredUpstream
// pins the fail-closed result of resolving a certificate principal whose role
// grants device:read through the real embedded IAM transport and its PEP.
//
// Upstream gap (#1906 Codex P1, Refs #646): the SPEC 107 platform permission
// vocabulary (device:read and the other platform scopes) is not declared by the
// pinned go-qrdb v0.19.0-alpha or go-quicbaas v0.12.0-alpha, and neither SDK
// gives this repository an API to declare a permission scope (go-qrdb
// permission.RegisterScope is for built-ins only; the per-tenant scope store
// lives inside go-quicbaas pkg/server). The pinned embedded transport also has
// no working PEP Check handler. Until the upstream declarations are tagged and
// adopted, the PEP cannot allow device:read, so the resolver must refuse the
// principal rather than grant the scope its role lists. When this test fails
// because the PEP starts deciding, adopt the upstream vocabulary and change it
// to assert device:read is granted; do not add a local scope, wildcard or
// fallback to make it pass.
func TestIAMCertificatePrincipals_DeviceReadStaysRefusedUntilTheVocabularyIsDeclaredUpstream(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	e.AddRole(t, "tenant-a", "reader", "device:read")
	e.AddUser(t, "tenant-a", "device-01@example.com", "device-01", quiciam.LifecycleActive, "reader")
	resolver, err := newIAMCertificatePrincipals(e.Client.User(), e.Client.Role(), e.Client.PEP())
	require.NoError(t, err)
	require.Contains(t, resolver.catalog, "device:read", "the catalog requests device:read for device operations")

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	var unresolved ErrCertificatePrincipalUnresolved
	require.ErrorAs(t, err, &unresolved, "an undecidable platform permission refuses the principal (fail closed)")
	assert.Contains(t, unresolved.Reason, "could not decide")
	assert.Nil(t, principal, "no principal, so no device:read scope, while the platform vocabulary is undeclared upstream")
}
