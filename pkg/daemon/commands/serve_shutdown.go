package commands

import (
	"context"
	"os"
	"syscall"

	platformrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/platform"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serveShutdowner answers POST /platform/shutdown in the serve command by
// signalling the serve loop, so the HTTP server, the Noise server and the
// daemon stop through the same coordinated path as on SIGTERM. That stop
// is always graceful: the request's Force and timeout are not used here.
type serveShutdowner struct{ sig chan<- os.Signal }

// Shutdown sends SIGTERM on the serve loop's signal channel without
// blocking; when a stop is already pending it answers success as well.
func (s serveShutdowner) Shutdown(_ context.Context, _ *platformv1.ShutdownRequest) (*platformv1.ShutdownResponse, error) {
	select {
	case s.sig <- syscall.SIGTERM:
	default: // a stop is already pending
	}
	return &platformv1.ShutdownResponse{
		Status: &platformv1.Status{Success: true, Message: "shutdown started"},
	}, nil
}

// platformShutdowner returns the Shutdowner the serve command wires into
// the platform REST router.
func platformShutdowner(sig chan<- os.Signal) platformrest.Shutdowner {
	return serveShutdowner{sig: sig}
}
