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

package installer

import (
	"context"
	"crypto/x509"
)

// IdentityEnroller enrols the node with the platform and returns the IDevID
// certificate its TPM then holds. It is the enrollment client every node
// runs: ACME enroll-01 or endorse-01 through the go-quicbaas SDK, whichever
// the platform configuration selects. The installer adds no enrollment code
// of its own; it only calls this seam.
type IdentityEnroller interface {
	EnrollIdentity(ctx context.Context) (*x509.Certificate, error)
}

// WithIdentityEnroller supplies the enrollment client a diskless-nbd install
// runs before it uses its NBD export. Without one, a diskless-nbd install is
// refused with ErrorTypeEnrollment.
func WithIdentityEnroller(e IdentityEnroller) InstallerOption {
	return func(i *installer) { i.enroller = e }
}

// enrollNBDIdentity enrols a diskless-nbd node before its first attach: the
// export authenticates the node by its IDevID, so the installer refuses to
// use the export until the node holds one. It runs before the TPM clear and
// before any disk is touched, so a failed enrollment changes no disk.
func (i *installer) enrollNBDIdentity(ctx context.Context) error {
	if i.enroller == nil {
		return ErrEnrollment("refusing to attach the NBD export", &EnrollmentError{
			Reason: "no enrollment client is configured",
		})
	}
	idevid, err := i.enroller.EnrollIdentity(ctx)
	if err != nil {
		return ErrEnrollment("refusing to attach the NBD export", &EnrollmentError{
			Reason: "enrollment failed",
			Err:    err,
		})
	}
	if idevid == nil {
		return ErrEnrollment("refusing to attach the NBD export", &EnrollmentError{
			Reason: "enrollment returned no IDevID certificate",
		})
	}
	i.logger.Info("[INSTALLER] diskless-nbd node enrolled",
		"idevid_subject", idevid.Subject.CommonName,
		"idevid_serial", idevid.SerialNumber.String())
	return nil
}
