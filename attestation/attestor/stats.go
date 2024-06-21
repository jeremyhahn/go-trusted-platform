package attestor

import (
	"context"

	"github.com/op/go-logging"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

type handler struct {
	logger   *logging.Logger
	attestor Attestor
}

func (h *handler) TagRPC(ctx context.Context, stats *stats.RPCTagInfo) context.Context {
	h.logger.Debug("TagRPC")
	return context.Background()
}

// HandleRPC processes the RPC stats.
func (h *handler) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	h.logger.Debug("HandleRPC: %+v", stats)
	// p, _ := peer.FromContext(ctx)
	// h.logger.Debugf("Received connection from: %v", p.Addr.String())
}

func (h *handler) TagConn(context.Context, *stats.ConnTagInfo) context.Context {
	h.logger.Debug("Tag Conn")
	return context.Background()
}

// HandleConn processes the Conn stats.
func (h *handler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnEnd:
		p, _ := peer.FromContext(ctx)
		verifierIP := parseVerifierIP(p.Addr)
		h.logger.Debug("attestor: verifier terminated the connection: %s")
		h.attestor.RemoveVerifierCABundle(verifierIP)
		break
	}
}
