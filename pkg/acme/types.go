package acme

import (
	"encoding/json"
	"errors"
	"log/slog"
)

// ACME status values of Account, Order, Authorization and Challenge objects.
// See https://tools.ietf.org/html/rfc8555#section-7.1.6 for details.
const (
	// StatusDeactivated = "deactivated"
	// StatusExpired     = "expired"
	// StatusInvalid     = "invalid"
	// StatusPending     = "pending"
	// StatusProcessing  = "processing"
	// StatusReady       = "ready"
	// StatusRevoked     = "revoked"
	// StatusUnknown     = "unknown"
	// StatusValid       = "valid"

	StatusValid       = "valid"       // Entity is valid (account, order, authorization, certificate)
	StatusPending     = "pending"     // Entity is pending (order, authorization, challenge)
	StatusProcessing  = "processing"  // Entity is processing (order, challenge)
	StatusInvalid     = "invalid"     // Entity is invalid (order, authorization, challenge)
	StatusDeactivated = "deactivated" // Entity is deactivated (account, authorization)
	StatusExpired     = "expired"     // Entity is expired (authorization, certificate)
	StatusRevoked     = "revoked"     // Entity is revoked (account, certificate)
	StatusReady       = "ready"       // Entity is ready (order)

	AuthzTypeDNS                 AuthzType = "dns"
	AuthzTypeIP                  AuthzType = "ip"
	AuthzTypePermanentIdentifier AuthzType = "permanent-identifier"
)

var (
	ErrInvalidAuthzType = errors.New("invalid authorization type")
)

// DirectoryResponse provides the ACME server's directory endpoints as per RFC 8555.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       Meta   `json:"meta"`
}

// Meta provides additional information about the ACME server.
type Meta struct {
	TermsOfService     string   `json:"termsOfService,omitempty"`
	Website            string   `json:"website,omitempty"`
	CAAIdentities      []string `json:"caaIdentities,omitempty"`
	ExternalAccountReq bool     `json:"externalAccountRequired,omitempty"`
}

type KeyMap map[string]interface{}

func (keyMap KeyMap) Equals(key KeyMap) bool {
	if keyMap["kty"] != key["kty"] {
		return false
	}
	if keyMap["n"] != key["n"] {
		return false
	}
	if keyMap["e"] != key["e"] {
		return false
	}
	if keyMap["crv"] != key["crv"] {
		return false
	}
	if keyMap["x"] != key["x"] {
		return false
	}
	if keyMap["y"] != key["y"] {
		return false
	}
	return true
}

func (keyMap KeyMap) String() ([]byte, error) {
	bytes, err := json.Marshal(keyMap)
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}
	return bytes, nil
}

type AuthzType string

func (authType AuthzType) String() string {
	return string(authType)
}

func ParseAuthzType(authzType string) (AuthzType, error) {
	switch authzType {
	case "dns":
		return AuthzTypeDNS, nil
	case "ip":
		return AuthzTypeIP, nil
	case "permanent-identifier":
		return AuthzTypePermanentIdentifier, nil
	default:
		return "", ErrInvalidAuthzType
	}
}
