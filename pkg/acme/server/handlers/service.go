package handlers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/server"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/peterhellberg/link"
)

var (
	ErrKIDAndJWKNotAllowed = errors.New("both kid and jwk not allowed in JWS header")
)

type RestServicer interface {
	AccountHandler(w http.ResponseWriter, r *http.Request)
	AuthorizationHandler(w http.ResponseWriter, r *http.Request)
	CertificateHandler(w http.ResponseWriter, r *http.Request)
	ChallengeHandler(w http.ResponseWriter, r *http.Request)
	DirectoryHandler(w http.ResponseWriter, r *http.Request)
	NewAccountHandler(w http.ResponseWriter, r *http.Request)
	NewNonceHandler(w http.ResponseWriter, r *http.Request)
	NewOrderHandler(w http.ResponseWriter, r *http.Request)
	OrderHandler(w http.ResponseWriter, r *http.Request)
	OrdersListHandler(w http.ResponseWriter, r *http.Request)
	OrderFinalizeHandler(w http.ResponseWriter, r *http.Request)
	RevokeCertHandler(w http.ResponseWriter, r *http.Request)
	KeyChangeHandler(w http.ResponseWriter, r *http.Request)

	// Non-RFC 8555 compliant handlers
	CABundleHandler(w http.ResponseWriter, r *http.Request)
}

const (
	externalAccountRequired = false
	nonceSize               = 16
)

type Params struct {
	ACMEConfig      *acme.Config
	CA              ca.CertificateAuthority
	CN              string
	DAOFactory      dao.Factory
	DeviceService   *device.Service
	DNSService      *dns.Service
	Logger          *logging.Logger
	TPM             tpm2.TrustedPlatformModule
	TLSPort         int
	TLSKeyAlgorithm x509.PublicKeyAlgorithm
	TLSStoreType    keystore.StoreType
}

type RestService struct {
	acmeConfig       *acme.Config
	baseRESTURI      string
	ca               ca.CertificateAuthority
	challengeMap     map[string]acme.ChallengeVerifierFunc
	consistencyLevel datastore.ConsistencyLevel
	keySerializer    keystore.KeySerializer
	logger           *logging.Logger
	nonceStore       *acme.NonceStore
	params           *Params
	tlsKeyAlgorithm  x509.PublicKeyAlgorithm
	tlsStoreType     keystore.StoreType
	tpm              tpm2.TrustedPlatformModule
	RestServicer
}

func NewRestService(params *Params) (RestServicer, error) {

	if params.ACMEConfig.Server == nil {
		params.Logger.Info("ACME server disabled")
		return nil, nil
	}

	baseRESTURI := strings.ReplaceAll(params.ACMEConfig.Server.DirectoryURL, "/acme/directory", "")
	keySerializer, err := keystore.NewSerializer(params.DAOFactory.SerializerType())
	if err != nil {
		return nil, fmt.Errorf("Failed to create key serializer")
	}
	challengeMap, err := acme.ParseConfiguredChallengeVerifiers(params.ACMEConfig.Server.Challenges)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse configured challenge verifiers: %v", err)
	}
	return &RestService{
		acmeConfig:       params.ACMEConfig,
		baseRESTURI:      baseRESTURI,
		ca:               params.CA,
		challengeMap:     challengeMap,
		consistencyLevel: params.DAOFactory.ConsistencyLevel(),
		keySerializer:    keySerializer,
		logger:           params.Logger,
		nonceStore:       acme.NewNonceStore(time.Minute * 10),
		params:           params,
		tlsKeyAlgorithm:  params.TLSKeyAlgorithm,
		tlsStoreType:     params.TLSStoreType,
		tpm:              params.TPM,
	}, nil
}

// Reusable responses
func (s *RestService) respondWithAccount(
	w http.ResponseWriter, account *entities.ACMEAccount, statusCode int) {

	nonce, err := acme.GenerateNonce(nonceSize)
	if err != nil {
		writeError(w, acme.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Link", fmt.Sprintf("%s/acme/directory>;rel=\"index\"", s.baseRESTURI))
	w.Header().Set("Location", s.accountURL(account))
	w.WriteHeader(statusCode)

	clientAccount := struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact,omitempty"`
		Orders  string   `json:"orders"`
	}{
		Status:  account.Status,
		Contact: account.Contact,
		Orders:  account.Orders,
	}

	json.NewEncoder(w).Encode(clientAccount)
}

func (s *RestService) accountURL(account *entities.ACMEAccount) string {
	return fmt.Sprintf("%s/acme/account/%d", s.baseRESTURI, account.ID)
}

func validateContactURLs(contacts []string) *entities.Error {
	for _, contact := range contacts {
		if strings.HasPrefix(contact, "mailto:") {
			emailAddress := strings.TrimPrefix(contact, "mailto:")
			// Check for 'hfields' and multiple 'addr-spec'
			if strings.Contains(emailAddress, "?") {
				return acme.InvalidContact("Invalid mailto URL: contains hfields")
			}
			if strings.Contains(emailAddress, ",") {
				return acme.InvalidContact("Invalid mailto URL: contains multiple addr-spec")
			}
			if _, err := mail.ParseAddress(emailAddress); err != nil {
				return acme.InvalidContact("Invalid mailto URL: invalid email address")
			}
		} else {
			return acme.UnsupportedContact("Unsupported contact URL scheme")
		}
	}
	return nil
}

func (s *RestService) orderResponse(w http.ResponseWriter, order *entities.ACMEOrder) {

	nonce, err := acme.GenerateNonce(nonceSize)
	if err != nil {
		writeError(w, acme.ServerInternal("Unable to generate nonce"))
		return
	}
	s.nonceStore.Add(nonce)

	clientOrder := struct {
		Status         string                    `json:"status"`
		Expires        string                    `json:"expires,omitempty"`
		Identifiers    []entities.ACMEIdentifier `json:"identifiers"`
		NotBefore      string                    `json:"notBefore,omitempty"`
		NotAfter       string                    `json:"notAfter,omitempty"`
		Error          *entities.Error           `json:"error,omitempty"`
		Authorizations []string                  `json:"authorizations"`
		Finalize       string                    `json:"finalize"`
		Certificate    string                    `json:"certificate,omitempty"`
	}{
		Status:         order.Status,
		Expires:        order.Expires,
		Identifiers:    order.Identifiers,
		NotBefore:      order.NotBefore,
		NotAfter:       order.NotAfter,
		Error:          order.Error,
		Authorizations: order.Authorizations,
		Finalize:       order.Finalize,
		Certificate:    order.Certificate,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", nonce)
	json.NewEncoder(w).Encode(clientOrder)

	fmt.Println(clientOrder)
}

func challengeResponse(w http.ResponseWriter, challenge *entities.ACMEChallenge) {
	clientChallenge := struct {
		Type      string          `json:"type"`
		URL       string          `json:"url"`
		Status    string          `json:"status"`
		Token     string          `json:"token"`
		Validated string          `json:"validated,omitempty"`
		Error     *entities.Error `json:"error,omitempty"`
	}{
		Type:      challenge.Type,
		URL:       challenge.URL,
		Status:    challenge.Status,
		Token:     challenge.Token,
		Validated: challenge.Validated,
		Error:     challenge.Error,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clientChallenge)
}

func writeError(w http.ResponseWriter, err *entities.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	if err.Status == 0 {
		err.Status = http.StatusInternalServerError
	}
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(err)
}

func (s *RestService) parseKID(r *http.Request) (*entities.ACMEAccount, []byte, error) {

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	jwsString := strings.TrimSpace(string(body))
	jws, err := jose.ParseSigned(jwsString, server.AllowedJOSEAlgorithms)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, nil, errors.New("no signatures found in JWS")
	}

	protectedHeader := jws.Signatures[0].Header

	if protectedHeader.JSONWebKey != nil && protectedHeader.KeyID != "" {
		return nil, nil, ErrKIDAndJWKNotAllowed
	}

	if protectedHeader.KeyID == "" {
		return nil, nil, errors.New("KID not found in JWS header")
	}

	if !s.nonceStore.Exists(protectedHeader.Nonce) {
		return nil, nil, acme.BadNonce("Invalid or missing Replay-Nonce")
	}

	accountID, err := parseAccountID(protectedHeader.KeyID)
	if err != nil {
		return nil, nil, errors.New("invalid account ID")
	}

	accountDAO, err := s.params.DAOFactory.ACMEAccountDAO()
	if err != nil {
		return nil, nil, errors.New("failed to create account DAO")
	}

	account, err := accountDAO.Get(accountID, s.consistencyLevel)
	if err != nil {
		return nil, nil, errors.New("account not found")
	}

	publicKey, err := keystore.Deserialize(account.Key)
	if err != nil {
		return nil, nil, errors.New("failed to decode account public key")
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return nil, nil, errors.New("invalid JWS signature")
	}

	return account, payload, nil
}

func keyAuthorization(token string, accountKey crypto.PublicKey) (string, error) {
	jwkThumbprint, err := jwkThumbprint(accountKey)
	if err != nil {
		return "", err
	}
	// Concatenate token and thumbprint
	return fmt.Sprintf("%s.%s", token, jwkThumbprint), nil
}

func jwkThumbprint(pubKey crypto.PublicKey) (string, error) {

	var jwk map[string]interface{}

	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		nBytes := key.N.Bytes()
		eBytes := big.NewInt(int64(key.E)).Bytes()
		jwk = map[string]interface{}{
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		}
	case *ecdsa.PublicKey:
		xBytes := key.X.Bytes()
		yBytes := key.Y.Bytes()
		jwk = map[string]interface{}{
			"crv": key.Curve.Params().Name,
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		}
	case ed25519.PublicKey:
		jwk = map[string]interface{}{
			"crv": "Ed25519",
			"kty": "OKP",
			"x":   base64.RawURLEncoding.EncodeToString(key),
		}
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK: %v", err)
	}

	// Compute the SHA-256 hash of the JWK
	var hasher hash.Hash = sha256.New()
	hasher.Write(jwkJSON)
	digest := hasher.Sum(nil)

	// Encode the hash in base64url
	thumbprint := base64.RawURLEncoding.EncodeToString(digest)
	return thumbprint, nil
}

func parseAccountID(accountURL string) (uint64, error) {
	pieces := strings.Split(accountURL, "/")
	accountID, err := strconv.ParseUint(pieces[len(pieces)-1], 10, 64)
	if err != nil {
		return 0, errors.New("invalid account ID")
	}
	return accountID, nil
}

func keyToID(key interface{}) (string, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(keyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func keyToString(key interface{}) string {
	keyBytes, _ := json.Marshal(key)
	return base64.RawURLEncoding.EncodeToString(keyBytes)
}

func isValidDomainName(domain string) bool {
	// Implement domain name validation logic
	// For example, using regexp or net.ParseIP for IP addresses
	// Here, we'll use a simple placeholder
	return true
}

func GenerateID() (uint64, error) {
	id := make([]byte, nonceSize)
	n, err := rand.Read(id)
	if err != nil {
		return 0, err
	}
	if n != nonceSize {
		return 0, errors.New("failed to generate ID")
	}
	return util.NewID(id), nil
}

func GenerateToken() (string, error) {
	id := make([]byte, nonceSize)
	n, err := rand.Read(id)
	if err != nil {
		return "", err
	}
	if n != nonceSize {
		return "", errors.New("failed to generate token")
	}
	return base64.RawURLEncoding.EncodeToString(id), nil
}

func parseNextLinkHeaderFromRequest(req *http.Request) (int, error) {
	links := link.ParseRequest(req)
	for _, l := range links {
		if l.Rel == "next" {
			// Parse the URL
			u, err := url.Parse(l.URI)
			if err != nil {
				return 0, fmt.Errorf("invalid URL in next link: %v", err)
			}
			// Extract the ID from the last path segment
			idStr := path.Base(u.Path)
			id, err := strconv.Atoi(idStr)
			if err != nil {
				return 0, fmt.Errorf("invalid ID in next link: %v", err)
			}
			return id, nil
		}
	}
	return 0, fmt.Errorf("next link not found")
}

// // Parses the provided x509 signature algorithm string and returns a
// // jose.SignatureAlgorithm or keystore.ErrInvalidSignatureAlgorithm
// // if the algorithm couldn't be parsed.
// func parseJOSESignatureAlgorithm(x509Alg string) (jose.SignatureAlgorithm, error) {
// 	switch strings.ToUpper(x509Alg) {
// 	case "SHA256-RSA":
// 		return jose.RS256, nil
// 	case "SHA384-RSA":
// 		return jose.RS384, nil
// 	case "SHA512-RSA":
// 		return jose.RS512, nil
// 	case "SHA256-RSAPSS":
// 		return jose.RS256, nil
// 	case "SHA384-RSAPSS":
// 		return jose.RS384, nil
// 	case "SHA512-RSAPSS":
// 		return jose.RS512, nil
// 	case "ECDSA-SHA256":
// 		return jose.ES256, nil
// 	case "ECDSA-SHA384":
// 		return jose.ES384, nil
// 	case "ECDSA-SHA512":
// 		return jose.ES512, nil
// 	case "ED25519":
// 		return jose.EdDSA, nil
// 	default:
// 		return "", ErrInvalidSignatureAlgorithm
// 	}
// }
