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

package adminclaim

import "fmt"

// ErrDependencyRequired is returned when the service is constructed
// without a dependency it cannot fail safe without.
type ErrDependencyRequired struct {
	Name string
}

func (e ErrDependencyRequired) Error() string {
	return fmt.Sprintf("adminclaim: %s is required", e.Name)
}

// ErrInvalidRequestBody is returned when a request body cannot be decoded.
type ErrInvalidRequestBody struct {
	Cause error
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("adminclaim: invalid request body: %v", e.Cause)
}

func (e ErrInvalidRequestBody) Unwrap() error { return e.Cause }

// ErrChallengeUnknown is returned when a proof cites a challenge that was
// never issued, already spent, or has expired.
type ErrChallengeUnknown struct{}

func (e ErrChallengeUnknown) Error() string {
	return "adminclaim: challenge is unknown, spent or expired"
}

// ErrCertificateInvalid is returned when the presented admin certificate
// does not parse, does not chain to the configured anchor, is outside its
// validity window, or is not a client certificate.
type ErrCertificateInvalid struct {
	Reason string
	Cause  error
}

func (e ErrCertificateInvalid) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("adminclaim: admin certificate rejected: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("adminclaim: admin certificate rejected: %s", e.Reason)
}

func (e ErrCertificateInvalid) Unwrap() error { return e.Cause }

// ErrIdentityMismatch is returned when the presented certificate is valid
// but does not name the firstboot system admin.
type ErrIdentityMismatch struct {
	Presented string
	Expected  string
}

func (e ErrIdentityMismatch) Error() string {
	return fmt.Sprintf("adminclaim: certificate identity %q is not the system admin %q",
		e.Presented, e.Expected)
}

// ErrProofInvalid is returned when the signature over the challenge does
// not verify against the presented certificate's public key.
type ErrProofInvalid struct {
	Cause error
}

func (e ErrProofInvalid) Error() string {
	return fmt.Sprintf("adminclaim: possession proof rejected: %v", e.Cause)
}

func (e ErrProofInvalid) Unwrap() error { return e.Cause }

// ErrClaimTokenInvalid is returned when a claim token is missing, unknown,
// expired or already spent.
type ErrClaimTokenInvalid struct{}

func (e ErrClaimTokenInvalid) Error() string {
	return "adminclaim: claim token is missing, unknown, spent or expired"
}

// ErrMultiInstanceUnsupported is returned when the claim ceremony is
// invoked on a deployment that runs more than one platformd instance
// against one store and no store-wide completion lease is wired. The
// process-local completion lock serialises one instance only, and the
// SDK factor enrolment is not conditional, so two instances could both
// observe an unclaimed identity and each enrol a different
// authenticator — letting a copied bootstrap key retain admin access
// alongside the legitimate operator. Rather than serve a ceremony that
// is silently unsafe there, the route refuses. The deployment lifts it
// by wiring ServiceParams.Transactions, which it does once the store's
// compare-and-swap answers (#172; ProbeTransactions).
type ErrMultiInstanceUnsupported struct{}

// Error implements the error interface.
func (e ErrMultiInstanceUnsupported) Error() string {
	return "admin claim: the claim ceremony on a multi-instance deployment needs the store's " +
		"compare-and-swap to make its completion atomic across instances, and this store did not answer it (see #172)"
}

// ErrClaimInProgress is returned when another instance holds the claim's
// store-wide completion lease: a claim is completing elsewhere right now.
type ErrClaimInProgress struct{}

// Error implements the error interface.
func (e ErrClaimInProgress) Error() string {
	return "admin claim: another claim is completing; retry once it has finished"
}

// ErrCompletionLockUnavailable is returned when the store could not run
// the completion lease's transaction. The claim fails closed: no
// enrolment happens without the lease.
type ErrCompletionLockUnavailable struct {
	Err error
}

// Error implements the error interface.
func (e ErrCompletionLockUnavailable) Error() string {
	if e.Err == nil {
		return "admin claim: the completion lease is unavailable"
	}
	return "admin claim: the completion lease is unavailable: " + e.Err.Error()
}

// Unwrap returns the store error.
func (e ErrCompletionLockUnavailable) Unwrap() error { return e.Err }

// ErrAlreadyClaimed is returned when the admin identity already carries an
// operator-enrolled authenticator. Re-claiming would let anyone holding a
// copy of the bootstrap certificate displace the operator's passkey while
// they still hold it. Removing the last factor re-opens the ceremony by
// design — see the package doc on why permanence is not the goal.
type ErrAlreadyClaimed struct{}

func (e ErrAlreadyClaimed) Error() string {
	return "adminclaim: the system admin identity has already been claimed"
}

// ErrCeremonyRejected is returned when the SDK completes without error but
// reports the attestation as unverified.
type ErrCeremonyRejected struct{}

func (e ErrCeremonyRejected) Error() string {
	return "adminclaim: the SDK rejected the authenticator attestation"
}

// ErrAnchorUnreadable is returned when the configured trust anchor bundle
// cannot be read or contains no certificate.
type ErrAnchorUnreadable struct {
	Path  string
	Cause error
}

func (e ErrAnchorUnreadable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("adminclaim: cannot read admin trust anchor %q: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("adminclaim: admin trust anchor %q contains no certificate", e.Path)
}

func (e ErrAnchorUnreadable) Unwrap() error { return e.Cause }

// ErrTooManyOutstanding is returned when the pre-auth secret store is at
// capacity. It fails the new request rather than evicting a live one.
type ErrTooManyOutstanding struct {
	Limit int
}

func (e ErrTooManyOutstanding) Error() string {
	return fmt.Sprintf("adminclaim: too many outstanding claim secrets (limit %d)", e.Limit)
}

// ErrProofRejected is the single, deliberately uninformative rejection the
// claim endpoints return to a caller whose proof did not pass. The
// specific reason is logged server-side; returning it would let a caller
// probe the trust anchor, the identity rule and the challenge store
// independently of one another.
type ErrProofRejected struct{}

func (e ErrProofRejected) Error() string {
	return "adminclaim: admin credential proof rejected"
}
