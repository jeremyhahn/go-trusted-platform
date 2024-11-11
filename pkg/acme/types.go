package acme

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/deviceattest01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/dns01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/endorse01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/enroll01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/challenge/http01"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"golang.org/x/crypto/acme"
)

// ACME status values of Account, Order, Authorization and Challenge objects.
// See https://tools.ietf.org/html/rfc8555#section-7.1.6 for details.
const (
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

	ChallengeTypeEnroll01       ChallengeType = "enroll-01"
	ChallengeTypeDNS01          ChallengeType = "dns-01"
	ChallengeTypeHTTP01         ChallengeType = "http-01"
	ChallengeTypeEndorse01      ChallengeType = "endorse-01"
	ChallengeTypeDeviceAttest01 ChallengeType = "device-attest-01"

	// WARNING: magic ahead!
	// Challenge types that support dynamic port configuration, where
	// the port number is derived from the challenge type. Ex: "http-8080"
	// would serve the http-01 challenge type on port 8080, while "http-8081"
	// would serve the http-01 challenge type on port 8081. Likewise,
	// device-8080 would use port 8080 to serve the device-01 challenge
	// while device-8081 would use port 8081. If the challenge type is "-01"
	// type, the port number will default to port 80 instead of port 1.
	DynamicChallengeTypeHTTPX   ChallengeType = "http"
	DynamicChallengeTypeEnrollX ChallengeType = "enroll"
)

var (
	ErrInvalidAuthzType            = errors.New("acme: invalid authorization type")
	ErrInvalidChallengeType        = errors.New("acme: invalid challenge type")
	ErrAccountAlreadyExists        = errors.New("acme: account already exists")
	ErrInvalidPortNumber           = errors.New("acme: invalid port number")
	ErrInvalidCertRequest          = errors.New("acme: invalid certificate request")
	ErrChallengeNotFound           = errors.New("acme: challenge not found")
	ErrMissingEnrollmentConfig     = errors.New("acme: missing enrollment configuration")
	ErrCrossSignerSameDirectoryURL = errors.New("acme: cross-signer directory URL must be different from primary directory URL")

	AuthzMap = map[string]AuthzType{
		AuthzTypeDNS.String():                 AuthzTypeDNS,
		AuthzTypeIP.String():                  AuthzTypeIP,
		AuthzTypePermanentIdentifier.String(): AuthzTypePermanentIdentifier,
	}

	ChallengeMap = map[string]ChallengeVerifierFunc{
		ChallengeTypeDeviceAttest01.String(): deviceattest01.Verify,
		ChallengeTypeDNS01.String():          dns01.Verify,
		ChallengeTypeEndorse01.String():      endorse01.Verify,
		ChallengeTypeEnroll01.String():       enroll01.Verify,
		ChallengeTypeHTTP01.String():         http01.Verify,
	}

	DynamicChallengeMap = map[string]ChallengeVerifierFunc{
		DynamicChallengeTypeHTTPX.String():   http01.Verify,
		DynamicChallengeTypeEnrollX.String(): enroll01.Verify,
	}

	AuthzDNSChallengeMap = map[string]bool{
		ChallengeTypeHTTP01.String(): true,
		ChallengeTypeDNS01.String():  true,
	}

	AuthzPermanentIdChallengeMap = map[string]bool{
		ChallengeTypeEndorse01.String():      true,
		ChallengeTypeDeviceAttest01.String(): true,
	}
)

// Directory provides the ACME server's directory endpoints as per RFC 8555.
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

type ChallengeVerifierFunc func(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	authzValue, challengePort, challengeToken, expectedKeyAuth string) error

type AuthzType string

func (authType AuthzType) String() string {
	return string(authType)
}

type ChallengeType string

func (challengeType ChallengeType) String() string {
	return string(challengeType)
}

func ParseAuthzType(authzType string) (AuthzType, error) {
	switch authzType {
	case AuthzTypeDNS.String():
		return AuthzTypeDNS, nil
	case AuthzTypeIP.String():
		return AuthzTypeIP, nil
	case AuthzTypePermanentIdentifier.String():
		return AuthzTypePermanentIdentifier, nil
	default:
		return "", ErrInvalidAuthzType
	}
}

func ParseAuthzTypeFromChallengeType(challengeType string) (AuthzType, error) {

	switch ChallengeType(challengeType) {
	case ChallengeTypeHTTP01, ChallengeTypeDNS01:
		return AuthzTypeDNS, nil
	case ChallengeTypeEnroll01, ChallengeTypeEndorse01, ChallengeTypeDeviceAttest01:
		return AuthzTypePermanentIdentifier, nil
	default:
		if IsHTTPxChallenge(challengeType) {
			return AuthzTypeDNS, nil
		}
		if IsEnrollXChallenge(challengeType) {
			return AuthzTypePermanentIdentifier, nil
		}
		return "", ErrInvalidAuthzType
	}
}

func ParseAuthzIDFromChallengeType(challengeType string) (acme.AuthzID, error) {
	switch ChallengeType(challengeType) {

	case ChallengeTypeHTTP01, ChallengeTypeDNS01:
		return acme.AuthzID{Type: AuthzTypeDNS.String()}, nil

	case ChallengeTypeEnroll01, ChallengeTypeEndorse01, ChallengeTypeDeviceAttest01:
		return acme.AuthzID{Type: AuthzTypePermanentIdentifier.String()}, nil

	default:
		if IsHTTPxChallenge(challengeType) {
			return acme.AuthzID{Type: AuthzTypeDNS.String()}, nil
		}
		if IsEnrollXChallenge(challengeType) {
			return acme.AuthzID{Type: AuthzTypePermanentIdentifier.String()}, nil
		}
		return acme.AuthzID{}, ErrInvalidAuthzType
	}
}

func ParseChallengeType(challengeType string) (ChallengeType, error) {
	switch challengeType {

	case ChallengeTypeHTTP01.String():
		return ChallengeTypeHTTP01, nil

	case ChallengeTypeDNS01.String():
		return ChallengeTypeDNS01, nil

	case ChallengeTypeEndorse01.String():
		return ChallengeTypeEndorse01, nil

	case ChallengeTypeEnroll01.String():
		return ChallengeTypeEnroll01, nil

	default:
		id, _, err := ParseChallengeAsDynamicPortAssignment(challengeType)
		if err != nil {
			return "", err
		}
		if _, ok := DynamicChallengeMap[id]; ok {
			return ChallengeType(challengeType), nil
		}
		return "", ErrInvalidAuthzType
	}
}

type Nonce struct {
	nonce string
}

func NewNonce(nonce []byte) *Nonce {
	return &Nonce{nonce: string(nonce)}
}

func (n *Nonce) Nonce() (string, error) {
	return n.nonce, nil
}

// Parse the port number from the challenge type. Ex: "http-8080" would
// use port 8080 while "http-8081" would use port 8081.
// If the challenge type is "http-01", use port 80 (per RFC 8555)
func ParseChallengeAsDynamicPortAssignment(challengeType string) (string, string, error) {

	pieces := strings.Split(challengeType, "-")
	if len(pieces) < 1 {
		return "", "", ErrInvalidChallengeType
	}

	var port int
	var name, sPort string
	var err error

	if len(pieces) > 1 {

		// Parse the port number from the last octect - ex: -01
		sPort = pieces[len(pieces)-1]
		port, err = strconv.Atoi(sPort)
		if err != nil {
			return "", "", ErrInvalidChallengeType
		}

		// Make sure its a valid port number
		if err != nil || port < 1 || port > 65535 {
			return "", "", ErrInvalidPortNumber
		}

		// Parse the challenge "name" (all the components to the left
		// of the last element). Ex: "http-01" would result in the
		// name "http".
		namePieces := pieces[:len(pieces)-1]
		name = strings.Join(namePieces, "-")
	}

	// If the challenge type is "*-01", resulting in port 1, use port 80 instead
	if port < 2 {
		sPort = "80"
	}

	return name, sPort, nil
}

// Parses the list of ACME challenges defined in the platform configuration file
func ParseConfiguredChallengeVerifiers(challenges []string) (map[string]ChallengeVerifierFunc, error) {

	verifiers := make(map[string]ChallengeVerifierFunc, len(challenges))

	for _, challenge := range challenges {

		// This is a standard RFC compliant challenge that doesn't
		// support dynamic port assignments.
		if verifier, ok := ChallengeMap[challenge]; ok {
			verifiers[challenge] = verifier
			continue
		}

		// Parse the challenge "name" (all components to the left of the
		// last element), and port number (the last element) from the
		// challenge type.
		_type, _, err := ParseChallengeAsDynamicPortAssignment(challenge)
		if err != nil {
			return nil, err
		}

		// This challenge type supports dynamic port assignment
		if _, ok := DynamicChallengeMap[_type]; ok {
			switch _type {

			case DynamicChallengeTypeHTTPX.String():
				verifiers[challenge] = http01.Verify
				continue

			case DynamicChallengeTypeEnrollX.String():
				verifiers[challenge] = enroll01.Verify
				continue
			}
		}

		return nil, ErrInvalidChallengeType
	}

	return verifiers, nil
}

func IsHTTPxChallenge(challengeType string) bool {
	return strings.HasPrefix(challengeType, "http-")
}

func IsEnrollXChallenge(challengeType string) bool {
	return strings.HasPrefix(challengeType, "enroll-")
}

func GenerateAccountID(pubKey crypto.PublicKey) uint64 {
	return keystore.PublicKeyID(pubKey, serializer.SERIALIZER_JSON)
}

func GenerateOrderID(authzID acme.AuthzID) uint64 {
	id := fmt.Sprintf("%s:%s", authzID.Type, authzID.Value)
	return util.NewID([]byte(id))
}
