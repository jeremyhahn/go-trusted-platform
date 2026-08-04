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

package commands

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// grpcMigrationCoordinator is the source-side driver of a VM migration handshake.
// It dials the destination platformd's gRPC endpoint over mutual TLS (the shared
// platform CA trust root), asks it to stand up a receiver (PrepareMigration), and
// later commits or aborts that receiver (FinalizeMigration). It implements
// compute.MigrationCoordinator.
//
// The receiver token returned by PrepareMigration is retained keyed by the
// (destination, source instance) pair so Finalize can reference it — the
// compute.MigrationCoordinator seam intentionally does not thread the token
// through the engine, keeping the orchestrator free of transport identifiers.
type grpcMigrationCoordinator struct {
	// tlsConfigFor builds the mTLS client configuration used to authenticate to
	// a destination daemon. It is a seam so tests can inject credentials without
	// a live CA.
	tlsConfigFor func(ctx context.Context) (*tls.Config, error)

	// newPeer dials destination and returns a migration RPC client plus a close
	// function. It is a seam so tests substitute a fake peer without a network.
	newPeer func(ctx context.Context, destination string, tlsCfg *tls.Config) (migrationPeer, func() error, error)

	logger *logging.Logger

	mu      sync.Mutex
	pending map[string]string // destination|instanceID -> receiver id
}

// Compile-time proof the coordinator satisfies the engine seam.
var _ compute.MigrationCoordinator = (*grpcMigrationCoordinator)(nil)

// migrationPeer is the subset of platformv1.ComputeServiceClient the coordinator
// needs. Narrowing to two methods keeps the fake used in tests small.
type migrationPeer interface {
	PrepareMigration(ctx context.Context, in *platformv1.PrepareMigrationRequest, opts ...grpc.CallOption) (*platformv1.PrepareMigrationResponse, error)
	FinalizeMigration(ctx context.Context, in *platformv1.FinalizeMigrationRequest, opts ...grpc.CallOption) (*platformv1.FinalizeMigrationResponse, error)
}

// ErrMigrationPeer wraps a destination-daemon RPC failure.
type ErrMigrationPeer struct {
	Op    string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrMigrationPeer) Error() string {
	return fmt.Sprintf("migration coordinator: %s failed: %v", e.Op, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigrationPeer) Unwrap() error { return e.Cause }

// ErrMigrationPeerRejected is returned when the destination reports a
// non-success status for a prepare/finalize request.
type ErrMigrationPeerRejected struct {
	Op      string
	Message string
}

// Error returns a human-readable description of the error.
func (e ErrMigrationPeerRejected) Error() string {
	return fmt.Sprintf("migration coordinator: %s rejected by destination: %s", e.Op, e.Message)
}

// newGRPCMigrationCoordinator builds a coordinator that authenticates to peers
// with certificates issued by ca. It returns nil when ca is nil so the
// orchestrator fails closed (MigrateVM reports ErrMigrationNotConfigured).
func newGRPCMigrationCoordinator(ca migrationCertIssuer, logger *logging.Logger) *grpcMigrationCoordinator {
	if ca == nil {
		return nil
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &grpcMigrationCoordinator{
		tlsConfigFor: func(ctx context.Context) (*tls.Config, error) {
			return newMigrationClientTLSConfig(ctx, ca)
		},
		newPeer: dialMigrationPeer,
		logger:  logger,
		pending: make(map[string]string),
	}
}

// PrepareIncoming implements compute.MigrationCoordinator.
func (c *grpcMigrationCoordinator) PrepareIncoming(ctx context.Context, destination string, spec compute.MigrationSpec) (*compute.IncomingEndpoint, error) {
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, &ErrMigrationPeer{Op: "resolve destination", Cause: err}
	}

	tlsCfg, err := c.tlsConfigFor(ctx)
	if err != nil {
		return nil, &ErrMigrationPeer{Op: "build mTLS client", Cause: err}
	}
	peer, closePeer, err := c.newPeer(ctx, destination, tlsCfg)
	if err != nil {
		return nil, &ErrMigrationPeer{Op: "dial destination", Cause: err}
	}
	defer func() { _ = closePeer() }()

	resp, err := peer.PrepareMigration(ctx, &platformv1.PrepareMigrationRequest{
		VmId:   spec.InstanceID,
		VmName: spec.VMName,
		Mode:   string(spec.Mode),
		Spec:   toProtoMigrationSpec(spec.Config),
	})
	if err != nil {
		return nil, &ErrMigrationPeer{Op: "PrepareMigration", Cause: err}
	}
	if !resp.GetStatus().GetSuccess() {
		return nil, &ErrMigrationPeerRejected{Op: "PrepareMigration", Message: resp.GetStatus().GetMessage()}
	}

	c.mu.Lock()
	c.pending[pendingKey(destination, spec.InstanceID)] = resp.GetReceiverId()
	c.mu.Unlock()

	return &compute.IncomingEndpoint{
		URI:         fmt.Sprintf("tcp:%s:%d", host, resp.GetPort()),
		TLSHostname: resp.GetTlsHostname(),
	}, nil
}

// Finalize implements compute.MigrationCoordinator. commit is derived from
// streamErr: a nil stream error commits the received VM, any error aborts it.
func (c *grpcMigrationCoordinator) Finalize(ctx context.Context, destination string, spec compute.MigrationSpec, streamErr error) error {
	key := pendingKey(destination, spec.InstanceID)
	c.mu.Lock()
	receiverID := c.pending[key]
	delete(c.pending, key)
	c.mu.Unlock()

	if receiverID == "" {
		// Nothing was prepared (or it was already finalized); nothing to do.
		return nil
	}

	tlsCfg, err := c.tlsConfigFor(ctx)
	if err != nil {
		return &ErrMigrationPeer{Op: "build mTLS client", Cause: err}
	}
	peer, closePeer, err := c.newPeer(ctx, destination, tlsCfg)
	if err != nil {
		return &ErrMigrationPeer{Op: "dial destination", Cause: err}
	}
	defer func() { _ = closePeer() }()

	resp, err := peer.FinalizeMigration(ctx, &platformv1.FinalizeMigrationRequest{
		ReceiverId: receiverID,
		Commit:     streamErr == nil,
	})
	if err != nil {
		return &ErrMigrationPeer{Op: "FinalizeMigration", Cause: err}
	}
	if !resp.GetStatus().GetSuccess() {
		return &ErrMigrationPeerRejected{Op: "FinalizeMigration", Message: resp.GetStatus().GetMessage()}
	}
	return nil
}

// pendingKey composes the map key used to correlate a prepared receiver with its
// later finalize.
func pendingKey(destination, instanceID string) string {
	return destination + "|" + instanceID
}

// toProtoMigrationSpec projects a compute.InstanceConfig onto the wire spec the
// destination uses to launch a matching receiver.
func toProtoMigrationSpec(cfg *compute.InstanceConfig) *platformv1.VMMigrationSpec {
	if cfg == nil {
		return nil
	}
	return &platformv1.VMMigrationSpec{
		MemoryMb:    int32(cfg.Memory),
		Cpus:        int32(cfg.CPUs),
		DiskSize:    cfg.DiskSize,
		BootMode:    cfg.BootMode,
		SecureBoot:  cfg.SecureBoot,
		EnableKvm:   cfg.EnableKVM,
		TpmEnabled:  cfg.TPMEnabled,
		NetworkMode: cfg.NetworkMode,
		MacAddress:  cfg.MACAddress,
	}
}

// dialMigrationPeer is the production migrationPeer dialer. It opens an mTLS gRPC
// connection to destination and returns the compute service client.
func dialMigrationPeer(_ context.Context, destination string, tlsCfg *tls.Config) (migrationPeer, func() error, error) {
	conn, err := grpc.NewClient(destination, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, nil, err
	}
	return platformv1.NewComputeServiceClient(conn), conn.Close, nil
}

// newMigrationClientTLSConfig issues a short-lived client certificate from the
// platform CA and anchors the peer trust pool to the CA bundle, producing the
// mTLS client configuration used to authenticate to a destination daemon. It
// never sets InsecureSkipVerify.
func newMigrationClientTLSConfig(ctx context.Context, ca migrationCertIssuer) (*tls.Config, error) {
	if ca == nil {
		return nil, ErrMigrationTLSNoCA{}
	}

	req := &quicbaasca.CACertificateRequest{
		Subject:     quicbaasca.CASubject{CommonName: fmt.Sprintf("migration-peer-client-%s", randomToken())},
		Valid:       migrationCertValidityDays,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	issued, err := ca.IssueCertificate(ctx, req)
	if err != nil {
		return nil, &ErrMigrationTLSIssue{Role: "peer-client", Cause: err}
	}

	cert, err := tls.X509KeyPair(issued.CertificatePEM, issued.PrivateKeyPEM)
	if err != nil {
		return nil, &ErrMigrationTLSIssue{Role: "peer-client", Cause: err}
	}

	bundle := issued.CACertificatePEM
	if len(bundle) == 0 {
		bundle, err = ca.CABundle()
		if err != nil {
			return nil, &ErrMigrationTLSIssue{Role: "peer-client", Cause: err}
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, &ErrMigrationTLSIssue{Role: "peer-client", Cause: ErrMigrationTLSNoCA{}}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
