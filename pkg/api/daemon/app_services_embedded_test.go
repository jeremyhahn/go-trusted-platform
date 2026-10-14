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

package daemon

import (
	"context"
	"testing"
	"time"

	sdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestAppServices_EmbeddedSDK builds the services over the SDK client of a
// started quicbaas factory with the embedded transport, as the daemon does.
// That transport has no Messaging handlers, and its Cache handlers are keyed
// by method names the SDK's cache client does not send, so every cache and
// messaging call answers SERVICE_NOT_CONFIGURED rather than an internal error.
// Since go-quicbaas v0.14 the transport serves the Scheduler, so a scheduler
// call reaches the embedded scheduler instead.
func TestAppServices_EmbeddedSDK(t *testing.T) {
	factory, err := quicbaas.NewFactory(quicbaas.TestConfig(t), logging.DefaultLogger(), nil)
	require.NoError(t, err)
	require.NoError(t, factory.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		assert.NoError(t, factory.Stop(ctx))
	})
	require.NotNil(t, factory.SDK(), "the started factory composes an SDK client")

	servers := appServiceServersOver(func() sdk.Client { return factory.SDK() }, logging.DefaultLogger())
	for name, c := range appServiceCalls(servers) {
		st := status.Convert(c.call(context.Background()))
		if c.service == appservices.ServiceScheduler {
			assert.NotEqual(t, codes.Unavailable, st.Code(),
				"%s reaches the embedded scheduler: %s", name, st.Message())
			continue
		}
		require.Equal(t, codes.Unavailable, st.Code(), "%s: %s", name, st.Message())
		assert.Equal(t, c.service, notConfiguredServiceName(t, st), name)
	}

	_, err = servers.scheduler.GetStatus(context.Background(), &platformv1.GetSchedulerStatusRequest{})
	assert.NoError(t, err, "the embedded scheduler answers its status")
	_, err = servers.scheduler.ListJobs(context.Background(), &platformv1.ListSchedulerJobsRequest{})
	assert.NoError(t, err, "the embedded scheduler lists its jobs")
}
