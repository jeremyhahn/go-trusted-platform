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
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// defaultCATrustInstallPath is where InstallCACertificates writes the CA
// bundle. It must match defaultSystemTrustCertPath in pkg/app/app.go:
// start-up installs the bundle there.
const defaultCATrustInstallPath = "/usr/local/share/ca-certificates/trusted-platform-ca.crt"

// CAInitializer brings the node CA up for InitCA and returns it.
type CAInitializer func(ctx context.Context) (quicbaasca.CACertificateAuthority, error)

// WithCAInitializer sets the initializer InitCA runs when no CA is loaded.
func (s *CAGRPCService) WithCAInitializer(init CAInitializer) *CAGRPCService {
	s.initCA = init
	return s
}

// WithTrustInstallPath sets where the CA bundle is installed and removed.
func (s *CAGRPCService) WithTrustInstallPath(path string) *CAGRPCService {
	s.trustPath = path
	return s
}

// injectQuicBaaSCA hands the CA InitCA brings up to the embedded QuicBaaS
// CertificateService and its ceremony CA, as platformd serve does at
// start-up (pkg/daemon/commands/serve.go:1598-1605). Tests replace it.
var injectQuicBaaSCA = func(a *app.App, ca quicbaasca.CACertificateAuthority) error {
	return a.SetQuicBaaSCA(ca)
}

// ErrQuicBaaSCAInject is returned when the embedded QuicBaaS refuses the CA
// InitCA brought up.
type ErrQuicBaaSCAInject struct {
	Cause error
}

func (e ErrQuicBaaSCAInject) Error() string {
	return "embedded QuicBaaS refused the CA: " + e.Cause.Error()
}

func (e ErrQuicBaaSCAInject) Unwrap() error { return e.Cause }

// AppCAInitializer runs the app's CA bring-up path, (*app.App).LoadOrInitCA,
// the same path AttachNodeCA takes at start-up, then hands the CA to the
// embedded QuicBaaS CertificateService and ceremony CA as start-up does, so
// SDK certificate issuance and ceremonies use it. A refusal fails InitCA
// with ErrQuicBaaSCAInject. It returns nil for a nil app and for an app with
// no CA configuration: there is nothing InitCA can bring up, so the daemon
// expects no CA.
func AppCAInitializer(a *app.App) CAInitializer {
	if a == nil || a.CAConfig == nil {
		return nil
	}
	return func(ctx context.Context) (quicbaasca.CACertificateAuthority, error) {
		if err := a.LoadOrInitCA(ctx, nil); err != nil {
			return nil, err
		}
		if err := injectQuicBaaSCA(a, a.CA); err != nil {
			return nil, ErrQuicBaaSCAInject{Cause: err}
		}
		return a.CA, nil
	}
}

// InitCA initialises the node CA through the app's bring-up path. It is
// idempotent: an initialised CA answers "already initialised". Re-initialising
// an existing CA (Force) is not supported. Admin capability: catalog scope
// ca:create.
func (s *CAGRPCService) InitCA(ctx context.Context, req *platformv1.InitCARequest) (*platformv1.InitCAResponse, error) {
	// initMu serializes InitCA: concurrent calls run the initializer once,
	// and the later ones see the swapped CA as already initialised.
	s.initMu.Lock()
	defer s.initMu.Unlock()
	cur := s.authority()
	initialised := cur != nil && cur.IsInitialized()
	if initialised && req.GetForce() {
		return nil, status.Error(codes.FailedPrecondition, "re-initialising an existing CA is not supported")
	}
	if initialised {
		info, err := s.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
		if err != nil {
			return nil, err
		}
		return &platformv1.InitCAResponse{
			Status:    &platformv1.Status{Success: true, Message: "CA already initialised"},
			CaInfo:    info.GetCaInfo(),
			Timestamp: timestamppb.Now(),
		}, nil
	}
	if s.initCA == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}
	ca, err := s.initCA(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if ca == nil || !ca.IsInitialized() {
		return nil, status.Error(codes.Internal, "CA bring-up returned no initialised CA")
	}
	// The gRPC/UDS CA service, the REST CA handlers and the QUIC CA
	// handler read one CAHolder, so all three serve the new CA now. QUIC
	// device attestation (the device AK trust and boot CA) keeps the
	// start-up CA until platformd restarts.
	s.setAuthority(ca)
	return &platformv1.InitCAResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "CA initialised; the gRPC, REST and QUIC CA services serve it now; restart platformd for QUIC device attestation to use it",
		},
		CaInfo:    s.caInfoOf(ca),
		Timestamp: timestamppb.Now(),
	}, nil
}

// caTrustBundles returns the PEM bundle of the trusted root and the full
// bundle (root followed by the intermediate, when there is one), with their
// certificate counts.
func (s *CAGRPCService) caTrustBundles(ca quicbaasca.CACertificateAuthority) (rootPEM []byte, rootCount int32, fullPEM []byte, fullCount int32, err error) {
	root, err := ca.TrustedRoot()
	if err != nil {
		return nil, 0, nil, 0, err
	}
	if root == nil {
		return nil, 0, nil, 0, errors.New("CA has no trusted root")
	}
	rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
	fullPEM = append([]byte{}, rootPEM...)
	rootCount, fullCount = 1, 1
	if inter, ierr := ca.TrustedIntermediate(); ierr == nil && inter != nil {
		fullPEM = append(fullPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw})...)
		fullCount = 2
	}
	return rootPEM, rootCount, fullPEM, fullCount, nil
}

// InstallCACertificates writes the CA bundle (the root, plus the intermediate
// when IncludeIntermediates is set) to the system trust path through
// trust.InstallToSystemTrust. It is idempotent: an identical bundle already in
// place answers "already installed". Admin capability: catalog scope
// trust:write.
func (s *CAGRPCService) InstallCACertificates(ctx context.Context, req *platformv1.InstallCACertificatesRequest) (*platformv1.InstallCACertificatesResponse, error) {
	ca := s.authority()
	if ca == nil || !ca.IsInitialized() {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}
	rootPEM, rootCount, fullPEM, fullCount, err := s.caTrustBundles(ca)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	bundle, count := rootPEM, rootCount
	if req.GetIncludeIntermediates() {
		bundle, count = fullPEM, fullCount
	}
	if current, rerr := os.ReadFile(s.trustPath); rerr == nil && bytes.Equal(current, bundle) {
		return &platformv1.InstallCACertificatesResponse{
			Status:      &platformv1.Status{Success: true, Message: "CA certificates already installed"},
			InstallPath: s.trustPath,
			Timestamp:   timestamppb.Now(),
		}, nil
	}
	if err := trust.InstallToSystemTrust(bundle, s.trustPath); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &platformv1.InstallCACertificatesResponse{
		Status:                &platformv1.Status{Success: true, Message: "CA certificates installed; run update-ca-certificates to refresh the system trust store"},
		CertificatesInstalled: count,
		InstallPath:           s.trustPath,
		Timestamp:             timestamppb.Now(),
	}, nil
}

// UninstallCACertificates removes the CA bundle InstallCACertificates wrote.
// It is a no-op ("nothing installed") when no bundle is present and refuses a
// file holding anything this CA did not write. Admin capability: catalog
// scope trust:write.
func (s *CAGRPCService) UninstallCACertificates(ctx context.Context, req *platformv1.UninstallCACertificatesRequest) (*platformv1.UninstallCACertificatesResponse, error) {
	ca := s.authority()
	if ca == nil || !ca.IsInitialized() {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}
	rootPEM, rootCount, fullPEM, fullCount, err := s.caTrustBundles(ca)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	// Read before removing so the count names the bundle that matched.
	current, _ := os.ReadFile(s.trustPath)
	removed, err := trust.UninstallFromSystemTrust(s.trustPath, rootPEM, fullPEM)
	if err != nil {
		var mismatch trust.ErrSystemTrustBundleMismatch
		if errors.As(err, &mismatch) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !removed {
		return &platformv1.UninstallCACertificatesResponse{
			Status:    &platformv1.Status{Success: true, Message: "nothing installed"},
			Timestamp: timestamppb.Now(),
		}, nil
	}
	count := rootCount
	if bytes.Equal(current, fullPEM) {
		count = fullCount
	}
	return &platformv1.UninstallCACertificatesResponse{
		Status:              &platformv1.Status{Success: true, Message: "CA certificates removed; run update-ca-certificates to refresh the system trust store"},
		CertificatesRemoved: count,
		Timestamp:           timestamppb.Now(),
	}, nil
}
