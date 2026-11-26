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

package platform

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Shutdowner is the PlatformDaemon.Shutdown surface the REST route
// drives. (*daemon.Service) satisfies it.
type Shutdowner interface {
	Shutdown(ctx context.Context, req *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error)
}

// ErrShutdownUnavailable is returned when POST /platform/shutdown is hit
// on a node whose daemon was not wired into the REST router.
type ErrShutdownUnavailable struct{}

func (ErrShutdownUnavailable) Error() string {
	return "platform shutdown is not wired on this node"
}

// SetShutdowner wires the daemon that POST /platform/shutdown stops.
func (h *PlatformHandlers) SetShutdowner(s Shutdowner) {
	h.shutdowner = s
}

// Shutdown handles POST /api/v1/platform/shutdown. The body is an
// optional ShutdownRequest ({graceful, timeoutSeconds}); an empty body
// asks for a graceful shutdown. The 202 reply is written before the
// daemon's Shutdown runs, because Shutdown can stop the listener that
// would carry the reply.
func (h *PlatformHandlers) Shutdown(w http.ResponseWriter, r *http.Request) {
	if h.shutdowner == nil {
		h.respWriter.Error503(w, r, ErrShutdownUnavailable{})
		return
	}
	req := &platformv1.ShutdownRequest{Graceful: true}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusAccepted, &platformv1.ShutdownResponse{
		Status: &platformv1.Status{Success: true, Message: "shutdown started"},
	})
	shutdowner := h.shutdowner
	go func() {
		if _, err := shutdowner.Shutdown(context.Background(), req); err != nil {
			h.logger.Errorf("platform shutdown: %v", err)
		}
	}()
}
