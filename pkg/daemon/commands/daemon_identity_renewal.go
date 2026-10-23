package commands

import (
	"context"
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// daemonIdentityCertTargetName names platformd's own TLS identity in the
// platform renewal registry (#36).
const daemonIdentityCertTargetName = "daemon.platformd"

// daemonIdentityCertTarget registers the daemon's TLS identity with the one
// platform renewal sweep (#31) instead of running a second one. The sweep
// reads the certificate the listeners present now; when it is inside the
// renewal window, Reissue issues a fresh keystore-held identity into the
// slot that is not serving, through the same CA path boot provisioning uses,
// and stores it in serving, so the next handshake on every TLS listener
// presents it. Only then is the replaced slot revoked and its key deleted.
// A failure before the swap leaves the serving identity untouched and is
// returned; a failure to retire the replaced slot is logged and retried by
// the next sweep's Current.
//
// The one certificate carries both the ServerAuth and the ClientAuth EKU, so
// renewing it renews the daemon's client role too: there is no second
// certificate to track.
func daemonIdentityCertTarget(
	logger *logging.Logger,
	ca daemonIdentityCA,
	serving *daemon.ServingCertificate,
	dnsNames, ipStrings []string,
) *app.CertTarget {

	return &app.CertTarget{
		Name: daemonIdentityCertTargetName,
		Kind: app.CertKindDaemon,
		Current: func(ctx context.Context) (*x509.Certificate, error) {
			leaf, err := servedDaemonLeaf(serving)
			if err != nil {
				return nil, err
			}
			// Every sweep reads Current, so it is where a retirement that
			// failed after the last swap is retried. It never fails the read:
			// the served identity is unaffected either way.
			retireReplacedDaemonServerSlot(ctx, logger, ca, otherDaemonServerSlot(leaf.Subject.CommonName))
			return leaf, nil
		},
		Reissue: func(ctx context.Context) error {
			leaf, err := servedDaemonLeaf(serving)
			if err != nil {
				return err
			}
			active := leaf.Subject.CommonName
			issued, err := issueDaemonServerIdentity(ctx, logger, ca, active, dnsNames, ipStrings)
			if err != nil {
				return err
			}
			if err := serving.Store(issued); err != nil {
				// The new slot is not serving; the next sweep's Current
				// retires it and the old identity keeps serving.
				return err
			}
			retireReplacedDaemonServerSlot(ctx, logger, ca, active)
			return nil
		},
	}
}

// servedDaemonLeaf returns the leaf the listeners present now.
func servedDaemonLeaf(serving *daemon.ServingCertificate) (*x509.Certificate, error) {
	cert := serving.Current()
	if cert == nil || cert.Leaf == nil {
		return nil, ErrTLSIdentityNotProvisioned{}
	}
	return cert.Leaf, nil
}
