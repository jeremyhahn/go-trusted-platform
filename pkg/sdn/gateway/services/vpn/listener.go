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

package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

const (
	// maxRequestBytes bounds a request body: a quote, its PCRs, an IDevID
	// certificate and a posture report fit with room to spare.
	maxRequestBytes   = 1 << 20
	readHeaderTimeout = 10 * time.Second
	requestTimeout    = 30 * time.Second
	idleTimeout       = 2 * time.Minute
	// shutdownGrace is how long in-flight calls may finish once the
	// listener's context is cancelled; the rest are closed.
	shutdownGrace = 10 * time.Second
)

// ClientCASource yields the pool a device certificate must chain to. The
// platform anchor (*trust.Anchor) satisfies it. It is read on every
// handshake, so a rotated anchor applies to the next connection.
type ClientCASource interface {
	CAPool(ctx context.Context) (*x509.CertPool, error)
}

// ListenerDeps are the admission listener's TLS inputs.
type ListenerDeps struct {
	// Certificate is the gateway's server certificate.
	Certificate tls.Certificate
	// ClientCAs is the device-identity anchor.
	ClientCAs ClientCASource
	// Logger defaults to the service's logger.
	Logger *slog.Logger
}

// AdmissionListener is the mTLS-only HTTP binding of the client verbs
// (docs/vpn/api.md §5). A connection without a client certificate that
// chains to the device-identity anchor fails the handshake, so no handler
// runs for it. The handlers decode, call the Service and encode; every
// admission decision is the Service's.
type AdmissionListener struct {
	svc       *Service
	address   string
	cert      tls.Certificate
	clientCAs ClientCASource
	logger    *slog.Logger

	started atomic.Bool
	bound   atomic.Value // net.Addr
	done    chan struct{}
}

// NewAdmissionListener binds the listener to svc and the address of the
// service's Config.Listener.
func NewAdmissionListener(svc *Service, deps ListenerDeps) (*AdmissionListener, error) {
	switch {
	case svc == nil:
		return nil, &ErrDepsMissing{Dep: "service"}
	case len(deps.Certificate.Certificate) == 0:
		return nil, &ErrDepsMissing{Dep: "listener certificate"}
	case deps.ClientCAs == nil:
		return nil, &ErrDepsMissing{Dep: "listener client CA source"}
	}
	logger := deps.Logger
	if logger == nil {
		logger = svc.logger
	}
	listen := svc.cfg.Listener
	return &AdmissionListener{
		svc:       svc,
		address:   net.JoinHostPort(listen.BindHost, strconv.Itoa(listen.Port)),
		cert:      deps.Certificate,
		clientCAs: deps.ClientCAs,
		logger:    logger,
		done:      make(chan struct{}),
	}, nil
}

// Start binds the address and serves until ctx is cancelled; then it shuts
// down, releases the port and closes Done. A listener starts once.
func (l *AdmissionListener) Start(ctx context.Context) error {
	if !l.started.CompareAndSwap(false, true) {
		return &ErrAlreadyStarted{}
	}
	ln, err := net.Listen("tcp", l.address)
	if err != nil {
		l.started.Store(false)
		return &ErrListenerBind{Address: l.address, Cause: err}
	}
	l.bound.Store(ln.Addr())
	server := &http.Server{
		Handler:           l.routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       requestTimeout,
		WriteTimeout:      requestTimeout,
		IdleTimeout:       idleTimeout,
		// A refused handshake is logged by the server; keep it out of the
		// operator's default view, a scanner would otherwise flood it.
		ErrorLog: slog.NewLogLogger(l.logger.Handler(), slog.LevelDebug),
	}
	go l.serve(ctx, server, tls.NewListener(ln, l.tlsConfig()))
	l.logger.Info("vpn.listener: serving", slog.String("address", ln.Addr().String()))
	return nil
}

// Done is closed once a started listener has released its port.
func (l *AdmissionListener) Done() <-chan struct{} {
	return l.done
}

// Addr is the bound address, or nil before Start.
func (l *AdmissionListener) Addr() net.Addr {
	addr, ok := l.bound.Load().(net.Addr)
	if !ok {
		return nil
	}
	return addr
}

func (l *AdmissionListener) serve(ctx context.Context, server *http.Server, ln net.Listener) {
	defer close(l.done)
	served := make(chan error, 1)
	go func() { served <- server.Serve(ln) }()
	select {
	case err := <-served:
		// Serve closed the listener on its way out.
		l.logger.Error("vpn.listener: serving stopped", slog.Any("error", err))
		return
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		l.logger.Warn("vpn.listener: in-flight calls outlived the grace period; closing them", slog.Any("error", err))
		if err := server.Close(); err != nil {
			l.logger.Warn("vpn.listener: close failed", slog.Any("error", err))
		}
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		l.logger.Warn("vpn.listener: serving ended with an error", slog.Any("error", err))
	}
	l.logger.Info("vpn.listener: stopped", slog.String("address", ln.Addr().String()))
}

func (l *AdmissionListener) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		GetConfigForClient: l.handshakeConfig,
	}
}

// handshakeConfig reads the anchor for this handshake. With no anchor the
// handshake fails: an empty pool must never fall back to the system roots.
func (l *AdmissionListener) handshakeConfig(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	pool, err := l.clientCAs.CAPool(hello.Context())
	if err == nil && pool == nil {
		err = &ErrListenerTrust{}
	}
	if err != nil {
		l.logger.Warn("vpn.listener: refusing the handshake, no device-identity anchor", slog.Any("error", err))
		return nil, &ErrListenerTrust{Cause: err}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{l.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// listenerHandler serves one verb for an authenticated peer. It returns the
// response body and status, or the service's typed error.
type listenerHandler func(w http.ResponseWriter, r *http.Request, peer *calleradmission.Peer) (any, int, error)

func (l *AdmissionListener) routes() http.Handler {
	handlers := map[string]listenerHandler{
		http.MethodPost + " " + PathChallenges:            l.challenge,
		http.MethodPost + " " + PathAdmissions:            l.admit,
		http.MethodPost + " " + pathLeases + "{id}/renew": l.renew,
		http.MethodDelete + " " + pathLeases + "{id}":     l.disconnect,
	}
	mux := http.NewServeMux()
	for pattern, handle := range handlers {
		mux.Handle(pattern, l.bind(handle))
	}
	return mux
}

// bind resolves the mTLS peer and writes the handler's result or refusal.
func (l *AdmissionListener) bind(handle listenerHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := calleradmission.PeerFromTLS(r.TLS, r.RemoteAddr)
		if !ok {
			l.refuse(w, &ErrPeerRefused{Reason: calleradmission.ReasonNoIdentity})
			return
		}
		body, status, err := handle(w, r, peer)
		if err != nil {
			l.refuse(w, err)
			return
		}
		l.write(w, status, body)
	})
}

func (l *AdmissionListener) challenge(_ http.ResponseWriter, _ *http.Request, _ *calleradmission.Peer) (any, int, error) {
	nonce, err := l.svc.Challenge()
	if err != nil {
		return nil, 0, err
	}
	return ChallengeWire{Nonce: nonce, DataPlanes: l.svc.cfg.DataPlanes}, http.StatusOK, nil
}

func (l *AdmissionListener) admit(w http.ResponseWriter, r *http.Request, peer *calleradmission.Peer) (any, int, error) {
	var body AdmissionRequestWire
	if err := decodeBody(w, r, &body); err != nil {
		return nil, 0, err
	}
	req, err := body.request(peer)
	if err != nil {
		return nil, 0, err
	}
	lease, err := l.svc.Admit(r.Context(), req)
	if err != nil {
		return nil, 0, err
	}
	return l.leaseWire(lease), http.StatusCreated, nil
}

func (l *AdmissionListener) renew(w http.ResponseWriter, r *http.Request, peer *calleradmission.Peer) (any, int, error) {
	id := LeaseID(r.PathValue("id"))
	var body RenewalRequestWire
	if err := decodeBody(w, r, &body); err != nil {
		return nil, 0, err
	}
	ev, err := body.evidence()
	if err != nil {
		return nil, 0, err
	}
	if _, err := l.svc.OwnLease(r.Context(), id, peer); err != nil {
		return nil, 0, err
	}
	lease, err := l.svc.Renew(r.Context(), id, ev)
	if err != nil {
		return nil, 0, err
	}
	return l.leaseWire(lease), http.StatusOK, nil
}

func (l *AdmissionListener) disconnect(_ http.ResponseWriter, r *http.Request, peer *calleradmission.Peer) (any, int, error) {
	id := LeaseID(r.PathValue("id"))
	if _, err := l.svc.OwnLease(r.Context(), id, peer); err != nil {
		return nil, 0, err
	}
	if err := l.svc.Revoke(r.Context(), id, RevokeClient); err != nil {
		return nil, 0, err
	}
	return nil, http.StatusNoContent, nil
}

// leaseWire encodes a lease for the client. No data plane exposes its
// endpoint yet, so the lease's endpoint is empty.
func (l *AdmissionListener) leaseWire(lease *Lease) *LeaseWire {
	return LeaseToWire(lease, l.svc.cfg.RenewWindow, EndpointWire{})
}

// refuse writes the refusal class for err. The class is all the client
// learns; the full error stays in the gateway's log.
func (l *AdmissionListener) refuse(w http.ResponseWriter, err error) {
	refusal, status := RefusalOf(err)
	if status >= http.StatusInternalServerError {
		l.logger.Error("vpn.listener: call failed", slog.String("reason", string(refusal.Reason)), slog.Any("error", err))
	}
	l.write(w, status, refusal)
}

func (l *AdmissionListener) write(w http.ResponseWriter, status int, body any) {
	if body == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		l.logger.Warn("vpn.listener: writing the response failed", slog.Any("error", err))
	}
}

// decodeBody reads one JSON object, refusing unknown fields, trailing data
// and bodies over maxRequestBytes.
func decodeBody(w http.ResponseWriter, r *http.Request, into any) error {
	return DecodeRequest(http.MaxBytesReader(w, r.Body, maxRequestBytes), into)
}
