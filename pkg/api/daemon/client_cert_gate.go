package daemon

import (
	"context"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// The listeners that serve the diskless boot RPCs verify a client certificate
// only if one is presented (tls.VerifyClientCertIfGiven): a node asking for its
// boot certificate has none yet. That moves "a verified client certificate is
// required" from the handshake to the request, enforced here per method so no
// other RPC is weakened.

// grpcClientCertOptional are the gRPC methods that may arrive without a client
// certificate. BootDelivery is not among them: it must carry the certificate
// BootCertificate returned.
var grpcClientCertOptional = map[string]struct{}{
	platformv1.DeviceService_BootCertificate_FullMethodName: {},
}

// verifiedClientCert reports whether the connection presented a client
// certificate that chained to the listener's client CA pool.
func verifiedClientCert(state *tls.ConnectionState) bool {
	return state != nil && len(state.VerifiedChains) > 0
}

// grpcClientCertGate refuses every method not in grpcClientCertOptional unless
// the connection carries a verified client certificate.
func grpcClientCertGate(ctx context.Context, fullMethod string) error {
	if _, optional := grpcClientCertOptional[fullMethod]; optional {
		return nil
	}
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && verifiedClientCert(&info.State) {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, ErrClientCertRequired{Operation: fullMethod}.Error())
}

// ClientCertGateUnaryInterceptor enforces grpcClientCertGate on unary calls.
func ClientCertGateUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := grpcClientCertGate(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// ClientCertGateStreamInterceptor enforces grpcClientCertGate on streams.
func ClientCertGateStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := grpcClientCertGate(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// quicClientCertOptional reports whether the request may arrive without a
// client certificate: the boot-certificate sub-operation only.
func quicClientCertOptional(req *quicwire.Request) bool {
	return req.Opcode == quicwire.OpProvisioningCategory &&
		len(req.Payload) > 0 && req.Payload[0] == quicwire.DeviceSubBootCertificate
}

// grpcTCPServerTLS returns the gRPC TCP listener's transport-security options:
// its TLS credentials and, under mTLS, the client-certificate gate. It returns
// none when no TLS material is configured.
//
// A diskless node asking for its boot certificate has none yet, so under mTLS
// the handshake verifies a client certificate only if one is given
// (VerifyClientCertIfGiven) and the gate interceptors require one on every
// method but BootCertificate. BootDelivery and everything else still arrive
// with a verified leaf, on the same listener (#690). Fails closed: mTLS with
// no resolvable client CA pool is a typed error (#550).
func grpcTCPServerTLS(config *Config, logger *logging.Logger) ([]grpc.ServerOption, error) {
	if !config.grpcTLSMaterialPresent() {
		return nil, nil
	}
	// Prefer a USABLE in-memory certificate, fall back to files. This
	// mirrors grpcTLSMaterialPresent: keying on mere non-nilness would
	// attach a structurally empty in-memory certificate even when a valid
	// file pair is configured (#32).
	var cert tls.Certificate
	if tlsCertificateUsable(config.TLSCertificate) {
		cert = *config.TLSCertificate
	} else {
		var err error
		cert, err = tls.LoadX509KeyPair(config.GRPCTLSCertFile, config.GRPCTLSKeyFile)
		if err != nil {
			return nil, ErrTLSConfigFailed{Reason: "gRPC: " + err.Error()}
		}
	}
	tlsConfig, err := newServerTLSConfig(config, transportGRPCTCP, cert)
	if err != nil {
		return nil, err
	}
	var opts []grpc.ServerOption
	if tlsConfig.ClientCAs != nil {
		// The handshake only verifies a certificate the client offers;
		// the interceptors require one per method except BootCertificate.
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		opts = append(opts,
			grpc.ChainUnaryInterceptor(ClientCertGateUnaryInterceptor()),
			grpc.ChainStreamInterceptor(ClientCertGateStreamInterceptor()))
		logger.Info("gRPC TCP server mTLS enabled", "addr", config.GRPCListenAddr)
	}
	return append(opts, grpc.Creds(credentials.NewTLS(tlsConfig))), nil
}

// quicServerMTLS turns on mTLS for the QUIC listener when the configuration
// enables it, and does nothing otherwise. Like gRPC, the handshake verifies a
// client certificate only if one is given and the handler requires one on
// every request but a boot-certificate request (#690). mTLS is QUIC's only
// authentication when enabled, so it fails closed: no TLS config to enforce it
// on, or no resolvable client CA pool, refuses the transport (#550).
func quicServerMTLS(config *Config, tlsConfig *tls.Config, handler *QUICServiceHandler, logger *logging.Logger) error {
	if !config.EnableMTLS {
		return nil
	}
	if tlsConfig == nil {
		return ErrTransportAuthRequired{
			Transport: transportQUIC,
			Reason:    "mTLS is enabled but the QUIC server has no TLS configuration to enforce it on",
		}
	}
	clientCAPool, err := resolveMTLSClientCAPool(config, transportQUIC)
	if err != nil {
		return err
	}
	tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	tlsConfig.ClientCAs = clientCAPool
	if handler != nil {
		handler.RequireClientCert()
	}
	logger.Info("QUIC server mTLS enabled on TLS config")
	return nil
}

// clientCertRefusal is the response for a request that needed a verified client
// certificate and had none, or nil when the request may proceed.
func (h *QUICServiceHandler) clientCertRefusal(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if !h.requireClientCert.Load() || quicClientCertOptional(req) || verifiedClientCert(quic.ConnectionTLS(ctx)) {
		return nil
	}
	return h.errorResponse(quicwire.StatusUnauthorized, ErrClientCertRequired{Operation: "QUIC opcode"})
}
