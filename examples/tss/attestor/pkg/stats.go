package main

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
)

type handler struct {
	logger        *logging.Logger
	attestor      Attestor
	secureService *SecureAttestor
}

func (h *handler) TagRPC(ctx context.Context, stats *stats.RPCTagInfo) context.Context {
	return ctx
}

func (h *handler) HandleRPC(ctx context.Context, stats stats.RPCStats) {
}

func (h *handler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *handler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnBegin:
		p, _ := peer.FromContext(ctx)
		verifierIP := parseVerifierIP(p.Addr)
		h.logger.Debugf("stats-handler: accepting new verifier connection: %s", verifierIP)
		h.secureService.OnConnect()

	case *stats.ConnEnd:
		p, _ := peer.FromContext(ctx)
		verifierIP := parseVerifierIP(p.Addr)
		h.logger.Debugf("stats-handler: verifier terminated the connection: %s", verifierIP)
		h.secureService.Close(ctx, nil)
		ctx.Done()
	}
}
