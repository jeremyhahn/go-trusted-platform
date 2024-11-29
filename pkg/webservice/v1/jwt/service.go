package jwt

import (
	"crypto"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	ErrAuthorizationHeaderRequired = errors.New("jwt/service: authorization header required")
	ErrInvalidToken                = errors.New("jwt/service: invalid token")
	ErrInvalidUserClaim            = errors.New("jwt/service: invalid user id claim")
	ErrInvalidEmailClaim           = errors.New("jwt/service: invalid email claim")
)

type TokenClaims struct {
	Organizations  []uint64 `json:"orgs"`
	Services       []uint64 `json:"svcs"`
	UserID         uint64   `json:"uid"`
	WebAuthnClaims *webauthn.SessionData
	jwt.RegisteredClaims
}

type ServiceParams struct {
	Audience   string
	Expiration int
	Issuer     string
	KeyAttrs   *keystore.KeyAttributes
	Keyring    *platform.Keyring
}

type Service struct {
	params        ServiceParams
	signer        crypto.Signer
	signingMethod jwt.SigningMethod
}

func NewService(params ServiceParams) (*Service, error) {
	signingMethod, err := NewSigningMethod(params.KeyAttrs)
	if err != nil {
		return nil, err
	}
	signer, err := params.Keyring.Signer(params.KeyAttrs)
	if err != nil {
		return nil, err
	}
	return &Service{
		params:        params,
		signer:        signer,
		signingMethod: signingMethod,
	}, nil
}

func (service *Service) GenerateToken(user *entities.User) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(service.signingMethod, TokenClaims{
		UserID: user.ID,
		// Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{service.params.Audience},
			Issuer:   service.params.Issuer,
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(
				now.Add(time.Minute * time.Duration(service.params.Expiration))),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	return token.SignedString(service.signer)
}

func (service *Service) ParseToken(
	w http.ResponseWriter, r *http.Request) (*jwt.Token, *TokenClaims, error) {

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return nil, nil, ErrAuthorizationHeaderRequired
	}
	tokenString = tokenString[len("Bearer "):]

	token, err := service.ParseTokenString(tokenString)
	if err != nil {
		return nil, nil, err
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, nil, ErrInvalidToken
	}

	return token, claims, nil
}

func (service *Service) ParseTokenString(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser()
	claims := &TokenClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, service.KeyFunc)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (service *Service) KeyFunc(token *jwt.Token) (interface{}, error) {
	return service.signer.Public(), nil
}

func (service *Service) PublicKey() crypto.PublicKey {
	return service.signer.Public()
}

func (service *Service) Verify(token *jwt.Token) error {
	if !token.Valid {
		return ErrInvalidToken
	}
	opts := jwt.WithAudience(service.params.Audience)
	return jwt.NewValidator(opts).Validate(token.Claims)
}
