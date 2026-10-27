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
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	localcertstore "github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// The installer enrols a diskless-nbd node through the App's enrollment
// client: there is no second one.
var _ installer.IdentityEnroller = (*App)(nil)

// enrollmentTimeout bounds one ACME device enrollment.
const enrollmentTimeout = 5 * time.Minute

// enrolledIdentity is what ACME device enrollment issued: the IAK and IDevID
// certificates and the chain of the CA that issued them.
type enrolledIdentity struct {
	iak    *x509.Certificate
	idevid *x509.Certificate
	chain  []*x509.Certificate
}

// deviceEnrollFunc runs one ACME device enrollment. It is the go-quicbaas
// SDK client's EnrollDevice unless a test replaces it.
type deviceEnrollFunc func(ctx context.Context, config *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error)

// acmeEnrollDevice enrols through the App's SDK ACME client.
func (app *App) acmeEnrollDevice(ctx context.Context, config *trustedca.ACMEEnrollmentConfig) (*enrolledIdentity, error) {
	result, err := app.ACMEClient.EnrollDevice(ctx, config)
	if err != nil {
		return nil, err
	}
	return &enrolledIdentity{
		iak:    result.IAKCertificate,
		idevid: result.IDevIDCertificate,
		chain:  result.Chain,
	}, nil
}

// enrollmentReady reports what EnrollIdentity needs and the App lacks.
func (app *App) enrollmentReady() error {
	if app.ACMEConfig == nil || app.ACMEConfig.Client == nil || app.ACMEConfig.Client.Enrollment == nil {
		return ErrEnrollmentUnavailable{Missing: "the acme.client.enrollment configuration"}
	}
	if app.TPM == nil {
		return ErrEnrollmentUnavailable{Missing: "an open TPM"}
	}
	if app.CA == nil {
		return ErrEnrollmentUnavailable{Missing: "the platform CA"}
	}
	return nil
}

// EnrollIdentity enrols the device with the OEM Enterprise / Privacy CA over
// ACME (enroll-01 or endorse-01, as acme.client.enrollment.challenge selects)
// through the go-quicbaas SDK client, stores the issued IAK and IDevID
// certificates, and returns the IDevID certificate (nil when the server
// issued none). It is the enrollment step of CompletePlatformIdentity and the
// installer's IdentityEnroller for a diskless-nbd install.
func (app *App) EnrollIdentity(ctx context.Context) (*x509.Certificate, error) {
	if err := app.enrollmentReady(); err != nil {
		return nil, err
	}
	enroll := app.enrollDevice
	if enroll == nil {
		if app.ACMEClient == nil {
			if err := app.InitACMEClient(ctx, true); err != nil {
				return nil, err
			}
		}
		enroll = app.acmeEnrollDevice
	}

	enrollCtx, cancelEnroll := context.WithTimeout(ctx, enrollmentTimeout)
	defer cancelEnroll()

	// Resolve ${PREFERRED_IP} macro before passing to go-trusted-ca
	// go-trusted-ca accepts plain IP addresses
	enrollmentIP := app.ACMEConfig.Client.Enrollment.IPAddress
	if enrollmentIP == "${PREFERRED_IP}" {
		enrollmentIP = util.PreferredIPv4().String()
		app.Logger.Info("Resolved PREFERRED_IP for ACME enrollment", "ip", enrollmentIP)
	}

	enrollConfig := &trustedca.ACMEEnrollmentConfig{
		Challenge:  app.ACMEConfig.Client.Enrollment.Challenge,
		IPAddress:  enrollmentIP,
		TPMModule:  trustedca.NewACMEXKMSTPMAdapter(app.TPM),
		CommonName: app.enrollmentName(),
	}
	enrolled, err := enroll(enrollCtx, enrollConfig)
	if err != nil {
		return nil, err
	}

	// Persist the CA that issued this device's identity, BEFORE the
	// leaves below, so their issuer is resolvable the moment they
	// land.
	//
	// The IAK and IDevID are issued by the ENROLLMENT SERVER's CA --
	// the control plane, acting as the enterprise/privacy CA -- not
	// by anything this node holds. CA.RootCertificate walks only the
	// local certificate store plus this CA's own cached root and
	// intermediate, so without the issuing chain in that store it
	// returns ErrRootNotFound for the node's own certificate. Three
	// callers depend on resolving it and all failed identically:
	// caller admission for attestation (every enrolled node compiled
	// a policy admitting nobody), the post-enrollment provisioning
	// TLS pool, and heartbeat.
	//
	// The chain arrives because enroll-01 now returns it after the
	// end-entity certificates, per RFC 8555 section 7.4.2
	// (go-xkms#556, released in v0.12.0-alpha). An older enrollment
	// server sends none, leaving Chain empty -- which is why this is
	// tolerant rather than fatal: the node still enrolls, and the
	// anchor gap surfaces where it is diagnosable.
	for _, issuer := range enrolled.chain {
		app.Logger.Info("Importing issuing chain certificate from ACME enrollment",
			slog.String("subject", issuer.Subject.CommonName),
			slog.String("issuer", issuer.Issuer.CommonName))
		if err := app.CA.ImportCertificate(ctx, issuer); err != nil {
			app.Logger.Error(err, slog.String("context", "Failed to import issuing chain certificate"),
				slog.String("subject", issuer.Subject.CommonName))
		}
	}
	if len(enrolled.chain) == 0 {
		app.Logger.Warn("ACME enrollment returned no issuing chain; this node cannot resolve the CA that issued its own IDevID",
			slog.String("remedy", "the enrollment server predates go-xkms v0.12.0-alpha (go-xkms#556)"))
	}

	// Import the IAK certificate from ACME enrollment
	if enrolled.iak != nil {
		app.Logger.Info("Importing IAK certificate from ACME enrollment",
			slog.String("subject", enrolled.iak.Subject.CommonName))
		if err := app.CA.ImportCertificate(ctx, enrolled.iak); err != nil {
			app.Logger.Error(err, slog.String("context", "Failed to import IAK certificate"))
		}
		// Persist to the TPM certificate store: the daemon's IDevID
		// API surface reads it from there, and its presence is what
		// marks the platform identity complete on later boots.
		if err := app.TPM.ProvisionIAKCert(enrolled.iak); err != nil {
			return nil, &WrappedError{Msg: "failed to store IAK certificate in the TPM certificate store", Err: err}
		}
		fmt.Println("IAK Certificate:")
		fmt.Println(localcertstore.ToString(enrolled.iak))
	}

	// Import the IDevID certificate from ACME enrollment
	if enrolled.idevid != nil {
		app.Logger.Info("Importing IDevID certificate from ACME enrollment",
			slog.String("subject", enrolled.idevid.Subject.CommonName))
		if err := app.CA.ImportCertificate(ctx, enrolled.idevid); err != nil {
			app.Logger.Error(err, slog.String("context", "Failed to import IDevID certificate"))
		}
		if err := app.TPM.ProvisionIDevIDCert(enrolled.idevid); err != nil {
			return nil, &WrappedError{Msg: "failed to store IDevID certificate in the TPM certificate store", Err: err}
		}
		fmt.Println("IDevID Certificate:")
		fmt.Println(localcertstore.ToString(enrolled.idevid))

		// Perform post-enrollment provisioning: fetch profile and activate
		// This uses mTLS with the IDevID certificate to authenticate
		profile, activateResp, provErr := app.FetchProfileAndActivate(ctx, enrolled.idevid)
		if provErr != nil {
			app.Logger.Warn("Post-enrollment provisioning failed (non-fatal)",
				slog.String("error", provErr.Error()))
		} else if profile != nil && activateResp != nil {
			app.Logger.Info("Post-enrollment provisioning completed",
				slog.String("serial", profile.SerialNumber),
				slog.Int("admitted_vlan", int(profile.AdmittedNetwork.VLAN)),
				slog.String("activation_status", activateResp.Status))
		}
	}
	return enrolled.idevid, nil
}
