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

package login

import (
	"net/http"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// DriverParams collects the driver's dependencies.
type DriverParams struct {
	// Client is the unified login boundary. A nil client is legal and
	// makes every ceremony fail closed with UnavailableError, which is
	// how a deployment without IAM behaves.
	Client UnifiedLoginClient

	// Binders are the per-factor HTTP adapters. Two binders claiming the
	// same factor type is a wiring defect and fails construction.
	Binders []Binder

	// SessionIssuer mints the credential a completed ceremony hands the
	// client. It is REQUIRED: a driver without one could only answer a
	// successful login with a credential this server's own inbound seam
	// rejects, so construction fails instead.
	SessionIssuer SessionIssuer

	Logger         *logging.Logger
	ResponseWriter response.HttpWriter
}

// Driver runs the unified login ceremony and writes its outcome. It is
// the only place the Begin/Finish sequence is implemented; a factor
// contributes a Binder, never a second copy of this flow.
type Driver struct {
	client  UnifiedLoginClient
	binders binders
	issuer  SessionIssuer
	logger  *logging.Logger
	writer  response.HttpWriter
}

// NewDriver constructs a Driver over the supplied binders. It fails when
// the logger or writer is absent — a driver that cannot report a refusal
// cannot refuse — when no session issuer is supplied, or when two binders
// claim the same factor type.
func NewDriver(params DriverParams) (*Driver, error) {
	if params.Logger == nil {
		return nil, &DriverConfigError{Field: "Logger"}
	}
	if params.ResponseWriter == nil {
		return nil, &DriverConfigError{Field: "ResponseWriter"}
	}
	// A driver with no issuer cannot produce a credential this server
	// accepts, so it must not exist. A nil client is legal (the login
	// surface is closed); a nil issuer is a wiring defect.
	if params.SessionIssuer == nil {
		return nil, &DriverConfigError{Field: "SessionIssuer"}
	}
	registry := make(binders, len(params.Binders))
	for _, binder := range params.Binders {
		if binder == nil {
			return nil, &DriverConfigError{Field: "Binders"}
		}
		factorType := binder.Type()
		if _, duplicate := registry[factorType]; duplicate {
			return nil, &DuplicateBinderError{Type: factorType}
		}
		registry[factorType] = binder
	}
	return &Driver{
		client:  params.Client,
		binders: registry,
		issuer:  params.SessionIssuer,
		logger:  params.Logger,
		writer:  params.ResponseWriter,
	}, nil
}

// Supports reports whether a binder is registered for the factor type.
// The router consults it to decide whether to register a factor's routes
// at all, rather than mounting a route that can only fail.
func (d *Driver) Supports(factorType quicbaas.FactorType) bool {
	_, ok := d.binders[factorType]
	return ok
}

// Begin opens a login ceremony for the factor type.
//
// For a challenge factor it answers with the binder's projection of the
// backbone's challenge. For a single-shot factor — one whose possession
// proof is the transport itself — it runs the finish step immediately and
// answers with the session, because there is nothing for the client to
// sign.
func (d *Driver) Begin(w http.ResponseWriter, r *http.Request, factorType quicbaas.FactorType) {
	binder, err := d.binder(factorType)
	if err != nil {
		d.fail(w, r, err)
		return
	}
	if d.client == nil {
		d.fail(w, r, &UnavailableError{})
		return
	}

	beginReq, err := binder.Begin(r)
	if err != nil {
		d.fail(w, r, err)
		return
	}
	begin, err := d.client.BeginLogin(r.Context(), beginReq)
	if err != nil {
		d.logger.Error(err, "unified BeginLogin failed")
		d.writer.Error401(w, r, err)
		return
	}
	if begin == nil {
		d.fail(w, r, &MissingChallengeError{Field: "response"})
		return
	}

	challenge, err := binder.Challenge(begin)
	if err != nil {
		d.fail(w, r, err)
		return
	}
	if challenge != nil {
		d.writer.Write(w, r, http.StatusOK, challenge)
		return
	}
	// Single-shot factor: possession was established out of band, so the
	// ceremony completes without a client round trip.
	d.finish(w, r, binder, begin.SessionID)
}

// Finish completes a challenge factor's ceremony with the proof the
// client produced from the Begin challenge, and answers with the session
// the platform issued for the principal the backbone resolved.
func (d *Driver) Finish(w http.ResponseWriter, r *http.Request, factorType quicbaas.FactorType) {
	binder, err := d.binder(factorType)
	if err != nil {
		d.fail(w, r, err)
		return
	}
	if d.client == nil {
		d.fail(w, r, &UnavailableError{})
		return
	}
	d.finish(w, r, binder, "")
}

// finish submits the proof and writes the session credential. sessionID
// is passed through to the binder: non-empty only for the single-shot
// path.
//
// Two distinct things happen here and the order matters. The BACKBONE
// authenticates: its bearer is the evidence the ceremony succeeded, and
// its identity names who it succeeded for. The PLATFORM then mints the
// credential its own inbound seam validates from that identity. The
// backbone bearer is never forwarded — nothing on this server can
// validate it (see SessionIssuer).
func (d *Driver) finish(w http.ResponseWriter, r *http.Request, binder Binder, sessionID string) {
	finishReq, err := binder.Finish(r, sessionID)
	if err != nil {
		d.fail(w, r, err)
		return
	}
	finish, err := d.client.FinishLogin(r.Context(), finishReq)
	if err != nil {
		d.logger.Error(err, "unified FinishLogin failed")
		d.writer.Error401(w, r, err)
		return
	}
	// Fail closed: an error-free response is not authentication. The
	// bearer is the only evidence the ceremony actually succeeded.
	if finish == nil || finish.FinishLoginResponse == nil || finish.Bearer == "" {
		d.fail(w, r, &NoBearerError{})
		return
	}
	// And a bearer with no identity is authentication of nobody: there is
	// no principal to mint a session for, so it is refused rather than
	// turned into an anonymous credential.
	if finish.Identity == nil {
		d.fail(w, r, &NoIdentityError{})
		return
	}
	bearer, expiresAt, err := d.issuer.IssueSession(finish.Identity)
	if err != nil {
		d.fail(w, r, &SessionIssueError{Cause: err})
		return
	}
	d.writer.Success200(w, r, newSession(bearer, expiresAt))
}

// binder resolves the binder for a factor type.
func (d *Driver) binder(factorType quicbaas.FactorType) (Binder, error) {
	binder, ok := d.binders[factorType]
	if !ok {
		return nil, &UnsupportedFactorError{Type: factorType}
	}
	return binder, nil
}

// fail maps a driver-side error onto its HTTP status and writes it.
//
// The mapping is deliberate: a client that sent a bad proof gets 400, a
// client whose proof did not authenticate gets 401, a deployment with no
// login backbone gets 403 (the surface exists but is closed), and a
// platform wiring defect gets 500 — never a status that reads as a
// client error when the platform is at fault.
func (d *Driver) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case *InvalidProofError, *MissingSessionError:
		d.writer.Error400(w, r, err)
	case *NoBearerError:
		d.logger.Error(err, "unified login returned no bearer")
		d.writer.Error401(w, r, err)
	case *NoIdentityError:
		d.logger.Error(err, "unified login returned a bearer with no identity")
		d.writer.Error401(w, r, err)
	case *SessionIssueError:
		d.logger.Error(err, "the platform could not issue the session credential")
		d.writer.Error500(w, r, err)
	case *UnavailableError:
		d.logger.Error(err, "unified login client not configured")
		d.writer.Error403(w, r, err, nil)
	case *UnsupportedFactorError:
		d.logger.Error(err, "unified login has no binder for the factor type")
		d.writer.Error500(w, r, err)
	case *MissingChallengeError:
		d.logger.Error(err, "unified BeginLogin returned an incomplete challenge")
		d.writer.Error500(w, r, err)
	default:
		d.writer.Error400(w, r, err)
	}
}
