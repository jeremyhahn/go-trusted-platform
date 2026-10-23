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

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

// provisioningListener binds a provisioning surface to the provisioning
// zone's gateway address as sdnEnv4 numbers it.
func provisioningListener(t *testing.T, a *App) *v1.Config {
	t.Helper()
	plan, err := a.NetworkPlan()
	require.NoError(t, err)
	numbering, err := plan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)
	return &v1.Config{Name: "provisioning", TLSPort: 8081, Surface: v1.SurfaceProvisioning, BindHost: numbering.Gateway.String()}
}

// TestApp_ValidateWebServices accepts a provisioning listener inside the
// provisioning zone beside a general one, and a node with no provisioning
// listener and no SDN section.
func TestApp_ValidateWebServices(t *testing.T) {
	a := &App{SDNConfig: sdnEnv4()}
	a.WebServices = []*v1.Config{{Name: "internal", TLSPort: 8443}, provisioningListener(t, a)}
	require.NoError(t, a.validateWebServices())

	require.NoError(t, (&App{WebServices: []*v1.Config{{Name: "internal", TLSPort: 8443}}}).validateWebServices())
	require.NoError(t, (&App{}).validateWebServices())
}

// TestApp_ValidateWebServices_Errors refuses a provisioning listener bound
// outside the zone, one on a node with no network plan, and one whose SDN
// section is invalid.
func TestApp_ValidateWebServices_Errors(t *testing.T) {
	a := &App{SDNConfig: sdnEnv4()}
	outside := provisioningListener(t, a)
	outside.BindHost = "192.0.2.10"
	a.WebServices = []*v1.Config{outside}
	err := a.validateWebServices()
	var wsErr ErrWebServiceValidation
	require.True(t, errors.As(err, &wsErr), "got %v", err)
	assert.Equal(t, "provisioning", wsErr.Name)
	var zoneErr *webservice.ErrProvisioningBindHostOutsideZone
	assert.True(t, errors.As(err, &zoneErr), "got %v", err)
	assert.Contains(t, err.Error(), "configuration is invalid")

	noPlan := &App{WebServices: []*v1.Config{{Name: "provisioning", TLSPort: 8081, Surface: v1.SurfaceProvisioning, BindHost: "10.4.0.1"}}}
	err = noPlan.validateWebServices()
	var planErr *webservice.ErrProvisioningNetworkPlanRequired
	require.True(t, errors.As(err, &planErr), "got %v", err)

	badSDN := &App{SDNConfig: &sdn.Config{Enabled: true}, WebServices: noPlan.WebServices}
	err = badSDN.validateWebServices()
	var sdnErr ErrSDNConfigValidation
	require.True(t, errors.As(err, &sdnErr), "got %v", err)
}

// A listener with no key section, and no IDevID to serve instead, is refused
// with a typed error where the dedicated key path used to dereference nil
// (Codex review 4948).
func TestApp_InitWebServiceKeyAttributes_RefusesNilKey(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger(), WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{}}
	ws := &v1.Config{Name: "provisioning", Surface: v1.SurfaceProvisioning, TLSPort: 9443}

	err := a.initWebServiceKeyAttributes(context.Background(), ws)

	var keyErr ErrWebServiceKeyRequired
	require.True(t, errors.As(err, &keyErr), "got %v", err)
	assert.Equal(t, "provisioning", keyErr.Name)
	assert.Contains(t, err.Error(), "has no key")
	assert.Empty(t, a.WebServiceKeyAttributes)
}

// A listener with a key section gets past the key check: here it stops at the
// next precondition, the platform key store this App does not have.
func TestApp_InitWebServiceKeyAttributes_KeyPresentPassesTheKeyCheck(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger(), WebServiceKeyAttributes: map[string]*xkmssdk.KeyAttributes{}}
	ws := &v1.Config{Name: "provisioning", Key: &common.KeyConfig{KeyAlgorithm: "ECDSA", StoreType: "software"}}

	err := a.initWebServiceKeyAttributes(context.Background(), ws)

	require.Error(t, err)
	var keyErr ErrWebServiceKeyRequired
	assert.False(t, errors.As(err, &keyErr), "got %v", err)
	assert.Contains(t, err.Error(), "SRK")
}
