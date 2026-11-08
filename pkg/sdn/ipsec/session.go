// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/secure"
)

// Session is one command connection to charon, reduced to the typed
// operations the controller drives. VICIDialer opens one over charon's VICI
// socket with govici; tests use a fake.
type Session interface {
	// LoadConn loads the named connection, replacing one of that name.
	LoadConn(ctx context.Context, name string, conn *Connection) error
	// UnloadConn unloads the named connection, and with it its trap.
	UnloadConn(ctx context.Context, name string) error
	// Conns lists the names of the connections charon holds.
	Conns(ctx context.Context) ([]string, error)
	// IKESAs lists the named connection's IKE_SAs, or every IKE_SA charon
	// holds when conn is empty.
	IKESAs(ctx context.Context, conn string) ([]HeldSA, error)
	// TerminateIKE destroys one IKE_SA without waiting for the peer to
	// confirm the delete.
	TerminateIKE(ctx context.Context, uniqueID string) error
	// LoadCert loads a certificate or a CRL.
	LoadCert(ctx context.Context, cred Credential) error
	// LoadToken loads the private key on a PKCS#11 token, logging in with
	// pin, or without a PIN when pin is nil. The PIN leaves the enclave
	// only for the send.
	LoadToken(ctx context.Context, key TokenKey, pin *secure.Secret) error
	// Done is closed when the connection ends.
	Done() <-chan struct{}
	// Close ends the session.
	Close() error
}

// EventStream is an event connection to charon, subscribed to ike-updown.
type EventStream interface {
	// Events delivers the ike-updown events. It is closed when the
	// connection ends.
	Events() <-chan IKEUpdown
	// Close ends the stream.
	Close() error
}

// Dialer opens connections to charon: command sessions and event streams
// are separate connections, so an event never waits behind a command.
type Dialer interface {
	Dial(ctx context.Context) (Session, error)
	Subscribe(ctx context.Context) (EventStream, error)
}

// CredentialKind is how charon files a loaded certificate.
type CredentialKind int

const (
	// CredentialEndEntity is the node's own tunnel certificate.
	CredentialEndEntity CredentialKind = iota
	// CredentialAuthority is a CA certificate peer certificates chain to.
	CredentialAuthority
	// CredentialCRL is a certificate revocation list.
	CredentialCRL
)

// Credential is a certificate or CRL for load-cert.
type Credential struct {
	Kind CredentialKind
	// DER is the encoded certificate or CRL.
	DER []byte
}

// TokenKey locates a private key on a PKCS#11 token.
type TokenKey struct {
	// Module is the name of the PKCS#11 module in charon's configuration
	// (charon.plugins.pkcs11.modules.<name>). Empty searches every module.
	Module string
	// Slot is the slot holding the token.
	Slot uint32
	// KeyID is the key's CKA_ID.
	KeyID []byte
}

// IKEUpdown is an ike-updown event: IKE_SAs that came up, or went down.
type IKEUpdown struct {
	// Up is true for SAs that came up.
	Up bool
	// SAs holds the IKE_SAs by connection name.
	SAs map[string]IKESA
	// Lost is true when events may have been dropped before this one, so
	// an SA may have come up unchecked. The SAs charon holds must be
	// audited. A Lost event may carry no SAs.
	Lost bool
}

// IKESA is the part of an IKE_SA's state the identity check reads.
type IKESA struct {
	UniqueID   string `vici:"uniqueid"`
	RemoteHost string `vici:"remote-host"`
	RemoteID   string `vici:"remote-id"`
}

// HeldSA is an IKE_SA charon holds, and the connection it belongs to.
type HeldSA struct {
	Conn string
	SA   IKESA
}

// Connection is a load-conn connection. Empty fields are left out of the
// message, so charon's defaults apply.
type Connection struct {
	Version     string             `vici:"version"`
	LocalAddrs  []string           `vici:"local_addrs"`
	RemoteAddrs []string           `vici:"remote_addrs"`
	Proposals   []string           `vici:"proposals"`
	Mobike      bool               `vici:"mobike"`
	Unique      string             `vici:"unique"`
	ReauthTime  string             `vici:"reauth_time"`
	DPDDelay    string             `vici:"dpd_delay"`
	Local       ConnAuth           `vici:"local"`
	Remote      ConnAuth           `vici:"remote"`
	Children    map[string]ChildSA `vici:"children"`
}

// ConnAuth is one side's authentication round of a Connection.
type ConnAuth struct {
	Auth       string `vici:"auth"`
	ID         string `vici:"id"`
	Revocation string `vici:"revocation"`
	// CACerts are PEM CA certificates the authenticating side's chain
	// must contain (charon's AUTH_RULE_CA_CERT): a certificate charon
	// could chain to another CA it holds is refused.
	CACerts []string `vici:"cacerts"`
}

// ChildSA is a CHILD_SA of a Connection.
type ChildSA struct {
	Mode         string   `vici:"mode"`
	StartAction  string   `vici:"start_action"`
	DPDAction    string   `vici:"dpd_action"`
	CloseAction  string   `vici:"close_action"`
	ESPProposals []string `vici:"esp_proposals"`
	ReplayWindow uint32   `vici:"replay_window"`
	LocalTS      []string `vici:"local_ts"`
	RemoteTS     []string `vici:"remote_ts"`
}
