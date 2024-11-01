package acme

import (
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// Error definitions as per RFC 8555
const (
	ErrTypeAccountDoesNotExist     = "accountDoesNotExist"
	ErrTypeAlreadyRevoked          = "alreadyRevoked"
	ErrTypeBadCSR                  = "badCSR"
	ErrTypeBadNonce                = "badNonce"
	ErrTypeBadPublicKey            = "badPublicKey"
	ErrTypeBadRevocationReason     = "badRevocationReason"
	ErrTypeBadSignatureAlgorithm   = "badSignatureAlgorithm"
	ErrTypeCAAError                = "caa"
	ErrTypeCompoundError           = "compound"
	ErrTypeConnectionError         = "connection"
	ErrTypeDNSError                = "dns"
	ErrTypeExternalAccountRequired = "externalAccountRequired"
	ErrTypeIncorrectResponse       = "incorrectResponse"
	ErrTypeInvalidContact          = "invalidContact"
	ErrTypeMalformedError          = "malformed"
	ErrTypeOrderNotReady           = "orderNotReady"
	ErrTypeRateLimited             = "rateLimited"
	ErrTypeRejectedIdentifier      = "rejectedIdentifier"
	ErrTypeServerInternal          = "serverInternal"
	ErrTypeTLSError                = "tls"
	ErrTypeUnauthorized            = "unauthorized"
	ErrTypeUnsupportedContact      = "unsupportedContact"
	ErrTypeUnsupportedIdentifier   = "unsupportedIdentifier"
	ErrTypeUserActionRequired      = "userActionRequired"
	ErrTypeAccountExists           = "accountExists"
)

func AccountDoesNotExist(detail string) *entities.Error {
	return entities.NewError("accountDoesNotExist", detail, http.StatusNotFound, nil)
}

func AlreadyRevoked(detail string) *entities.Error {
	return entities.NewError("alreadyRevoked", detail, http.StatusBadRequest, nil)
}

func BadAttestationStatement(detail string) *entities.Error {
	return entities.NewError("badAttestationStatement", detail, http.StatusBadRequest, nil)
}

func BadCSR(detail string) *entities.Error {
	return entities.NewError("badCSR", detail, http.StatusBadRequest, nil)
}

func BadNonce(detail string) *entities.Error {
	return entities.NewError("badNonce", detail, http.StatusBadRequest, nil)
}

func BadPublicKey(detail string) *entities.Error {
	return entities.NewError("badPublicKey", detail, http.StatusBadRequest, nil)
}

func BadRevocationReason(detail string) *entities.Error {
	return entities.NewError("badRevocationReason", detail, http.StatusBadRequest, nil)
}

func BadSignatureAlgorithm(detail string) *entities.Error {
	return entities.NewError("badSignatureAlgorithm", detail, http.StatusBadRequest, nil)
}

func CAAError(detail string) *entities.Error {
	return entities.NewError("caa", detail, http.StatusUnauthorized, nil)
}

func CompoundError(detail string, subproblems []entities.SubProblem) *entities.Error {
	return entities.NewError("compound", detail, http.StatusBadRequest, subproblems)
}

func ConnectionError(detail string) *entities.Error {
	return entities.NewError("connection", detail, http.StatusBadRequest, nil)
}

func DNSError(detail string) *entities.Error {
	return entities.NewError("dns", detail, http.StatusBadRequest, nil)
}

func ExternalAccountRequired(detail string) *entities.Error {
	return entities.NewError("externalAccountRequired", detail, http.StatusUnauthorized, nil)
}

func IncorrectResponse(detail string) *entities.Error {
	return entities.NewError("incorrectResponse", detail, http.StatusUnauthorized, nil)
}

func InvalidContact(detail string) *entities.Error {
	return entities.NewError("invalidContact", detail, http.StatusBadRequest, nil)
}

func MalformedError(detail string, subproblems []entities.SubProblem) *entities.Error {
	return entities.NewError("malformed", detail, http.StatusBadRequest, subproblems)
}

func OrderNotReady(detail string) *entities.Error {
	return entities.NewError("orderNotReady", detail, http.StatusForbidden, nil)
}

func RateLimited(detail string) *entities.Error {
	return entities.NewError("rateLimited", detail, http.StatusTooManyRequests, nil)
}

func RejectedIdentifier(detail string) *entities.Error {
	return entities.NewError("rejectedIdentifier", detail, http.StatusUnauthorized, nil)
}

func ServerInternal(detail string) *entities.Error {
	return entities.NewError("serverInternal", detail, http.StatusInternalServerError, nil)
}

func TLSError(detail string) *entities.Error {
	return entities.NewError("tls", detail, http.StatusBadRequest, nil)
}

func Unauthorized(detail string) *entities.Error {
	return entities.NewError("unauthorized", detail, http.StatusUnauthorized, nil)
}

func UnsupportedContact(detail string) *entities.Error {
	return entities.NewError("unsupportedContact", detail, http.StatusBadRequest, nil)
}

func UnsupportedIdentifier(detail string) *entities.Error {
	return entities.NewError("unsupportedIdentifier", detail, http.StatusBadRequest, nil)
}

func UserActionRequired(detail, instance string) *entities.Error {
	err := entities.NewError("userActionRequired", detail, http.StatusForbidden, nil)
	err.Instance = instance
	return err
}

func AccountExistsError(detail, location string) *entities.Error {
	err := entities.NewError("accountExists", detail, http.StatusConflict, nil)
	err.Instance = location
	return err
}
