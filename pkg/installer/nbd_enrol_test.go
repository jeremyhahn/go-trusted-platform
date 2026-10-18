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
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// recordingEnroller is the enrollment seam a test drives: it counts its
// calls, runs onEnroll at the moment the installer enrols, and returns its
// IDevID or error.
type recordingEnroller struct {
	idevid   *x509.Certificate
	err      error
	calls    int
	onEnroll func()
}

func (e *recordingEnroller) EnrollIdentity(context.Context) (*x509.Certificate, error) {
	e.calls++
	if e.onEnroll != nil {
		e.onEnroll()
	}
	return e.idevid, e.err
}

// enrolledNode is an enroller whose enrollment succeeds with an IDevID.
func enrolledNode(t *testing.T) *recordingEnroller {
	t.Helper()
	return &recordingEnroller{idevid: &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "node-7"},
	}}
}

// requireEnrollmentRefusal asserts err is an ErrEnrollment and returns its
// cause.
func requireEnrollmentRefusal(t *testing.T, err error) *EnrollmentError {
	t.Helper()
	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Equal(t, ErrorTypeEnrollment, installErr.Type)
	var enrollErr *EnrollmentError
	require.ErrorAs(t, err, &enrollErr)
	return enrollErr
}

func TestWithIdentityEnroller_WiresTheSeam(t *testing.T) {
	enroller := enrolledNode(t)
	inst := &installer{}

	WithIdentityEnroller(enroller)(inst)

	assert.Same(t, enroller, inst.enroller)
}

func TestWithIdentityEnroller_NilLeavesTheInstallRefused(t *testing.T) {
	r := newInstallRecorder(t, nbdLiveCmdline)
	WithIdentityEnroller(nil)(r.installer)

	err := r.installer.enrollNBDIdentity(context.Background())

	enrollErr := requireEnrollmentRefusal(t, err)
	assert.Contains(t, enrollErr.Reason, "no enrollment client")
}

func TestEnrollNBDIdentity_Enrolled(t *testing.T) {
	r := newInstallRecorder(t, nbdLiveCmdline)
	enroller := enrolledNode(t)
	r.installer.enroller = enroller

	require.NoError(t, r.installer.enrollNBDIdentity(context.Background()))
	assert.Equal(t, 1, enroller.calls)
}

func TestEnrollNBDIdentity_Refused(t *testing.T) {
	cause := errors.New("enroll-01: credential activation rejected")
	for name, tc := range map[string]struct {
		enroller *recordingEnroller
		reason   string
		cause    error
	}{
		"enrollment fails":      {enroller: &recordingEnroller{err: cause}, reason: "enrollment failed", cause: cause},
		"no IDevID certificate": {enroller: &recordingEnroller{}, reason: "no IDevID certificate"},
		"no enrollment client":  {reason: "no enrollment client"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newInstallRecorder(t, nbdLiveCmdline)
			if tc.enroller != nil {
				r.installer.enroller = tc.enroller
			}

			err := r.installer.enrollNBDIdentity(context.Background())

			enrollErr := requireEnrollmentRefusal(t, err)
			assert.Contains(t, enrollErr.Reason, tc.reason)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause, "the enrollment client's error is kept")
			}
		})
	}
}

// The node enrols before Install reads its export's attachment or takes
// /dev/nbd0 as the target: the export admits only the IDevID.
func TestInstall_DisklessNBDEnrolsBeforeItUsesTheExport(t *testing.T) {
	r := newInstallRecorder(t, nbdLiveCmdline)
	r.installer.sysfsRoot = attachedNBDSysfs(t)
	enroller := enrolledNode(t)
	enroller.onEnroll = func() {
		assert.Equal(t, "/dev/sda", r.installer.config.Disk.Device, "the export was taken as the target before enrollment")
		assert.Empty(t, *r.modprobes, "the TPM was cleared before enrollment")
		r.disk.AssertNotCalled(t, "CreatePartitionTable", mock.Anything, mock.Anything)
	}
	r.installer.enroller = enroller
	r.disk.On("CreatePartitionTable", mock.Anything, PartitionTableGPT).Return(errors.New("stop at the disk"))

	err := r.installer.Install(context.Background())

	require.ErrorContains(t, err, "stop at the disk")
	assert.Equal(t, 1, enroller.calls)
	assert.Equal(t, nbdTargetDevice, r.installer.config.Disk.Device)
}

// A failed enrollment is ErrorTypeEnrollment, and the install stops there:
// the export is not used, the TPM is not cleared and no disk is touched,
// even with the export attached.
func TestInstall_EnrollmentFailureTouchesNoDisk(t *testing.T) {
	cause := errors.New("endorse-01: EAB rejected")
	r := newInstallRecorder(t, nbdLiveCmdline)
	r.installer.sysfsRoot = attachedNBDSysfs(t)
	r.installer.enroller = &recordingEnroller{err: cause}
	r.disk.On("CreatePartitionTable", mock.Anything, mock.Anything).Return(errors.New("disk touched")).Maybe()

	err := r.installer.Install(context.Background())

	requireEnrollmentRefusal(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Empty(t, *r.modprobes, "the TPM was cleared")
	r.disk.AssertNotCalled(t, "CreatePartitionTable", mock.Anything, mock.Anything)
	assert.Equal(t, "/dev/sda", r.installer.config.Disk.Device)
}

// An export that is not usable after a successful enrollment is its own
// refusal, ErrorTypeNBDTarget, not an enrollment failure.
func TestInstall_AttachRefusalAfterEnrollmentIsItsOwnError(t *testing.T) {
	r := newInstallRecorder(t, nbdLiveCmdline)
	r.installer.sysfsRoot = fakeNBDSysfs(t, map[string]string{"size": "16777216\n"})
	enroller := enrolledNode(t)
	r.installer.enroller = enroller

	err := r.installer.Install(context.Background())

	var installErr *InstallerError
	require.ErrorAs(t, err, &installErr)
	assert.Equal(t, ErrorTypeNBDTarget, installErr.Type)
	var enrollErr *EnrollmentError
	assert.False(t, errors.As(err, &enrollErr))
	assert.Equal(t, 1, enroller.calls)
}

func TestEnrollmentError(t *testing.T) {
	cause := errors.New("server unreachable")

	withCause := &EnrollmentError{Reason: "enrollment failed", Err: cause}
	assert.Equal(t, "enrollment failed: server unreachable", withCause.Error())
	assert.ErrorIs(t, withCause, cause)

	bare := &EnrollmentError{Reason: "no enrollment client is configured"}
	assert.Equal(t, "no enrollment client is configured", bare.Error())
	assert.NoError(t, bare.Unwrap())
}
