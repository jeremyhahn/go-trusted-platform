package tpmowner

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// SOPINHandoffFile is where firstboot stages an SO PIN it generated for a
// kms:// platform.so-pin, for platformd to store at the configured kms path
// before it resolves its secrets. It lives on the firstboot tmpfs handoff
// (mode 0600, root only) beside the LUKS recovery key escrow, and platformd
// shreds it after use.
const SOPINHandoffFile = "/run/platform/firstboot-handoff/so-pin"

const (
	kmsScheme         = "kms://"
	sopinEncodingNum  = "numeric"
	schemeSeparator   = "://"
	soPINQueryEnsure  = "ensure"
	soPINQueryLength  = "len"
	soPINQueryEncoder = "enc"
)

// ErrSOPINNotConfigured is returned when platform.so-pin is empty: firstboot
// has no SO PIN to take ownership with.
var ErrSOPINNotConfigured = errors.New("platform.so-pin is not configured")

// ErrSOPINLengthInvalid is the cause of a SOPINGenerateError when the
// requested SO PIN length is not positive.
var ErrSOPINLengthInvalid = errors.New("SO PIN length must be positive")

// entropy is the randomness an SO PIN is drawn from.
var entropy io.Reader = rand.Reader

// SOPINRefError is returned when platform.so-pin names an SO PIN firstboot
// cannot reproduce for platformd. It never carries the configured value,
// which may be the PIN itself.
type SOPINRefError struct {
	Reason string
}

// Error returns the error message.
func (e *SOPINRefError) Error() string {
	return fmt.Sprintf("tpmowner: platform.so-pin cannot be used to take TPM ownership: %s", e.Reason)
}

// SOPINGenerateError is returned when the entropy source fails while
// generating an SO PIN.
type SOPINGenerateError struct {
	Cause error
}

// Error returns the error message.
func (e *SOPINGenerateError) Error() string {
	return fmt.Sprintf("tpmowner: failed to generate the SO PIN: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *SOPINGenerateError) Unwrap() error { return e.Cause }

// SOPINRef is a parsed platform.so-pin: either a literal PIN, or a
// kms://<path>?ensure=true&len=<n>&enc=numeric reference whose value
// firstboot generates and platformd stores at KMSPath.
type SOPINRef struct {
	// Literal is the PIN when platform.so-pin is not a kms:// URI.
	Literal []byte
	// KMSPath is the secret path of a kms:// reference, the name the
	// quicbaas kms:// resolver reads (the URI without scheme or query).
	KMSPath string
	// Length is the number of digits of a generated SO PIN.
	Length int
}

// IsKMS reports whether the SO PIN lives in KMS at KMSPath.
func (r *SOPINRef) IsKMS() bool { return r.KMSPath != "" }

// ParseSOPINRef parses platform.so-pin as platformd resolves it (ParsePINs):
// a literal is the PIN, and a kms:// URI with ensure=true is generated on
// first use and stable after. Only those two forms can be reproduced by
// firstboot before platformd's KMS exists. The empty value (platformd would
// prompt) and DEFAULT_PASSWORD (platformd would generate a PIN and discard
// it) are refused, as is any other scheme.
func ParseSOPINRef(ref string) (*SOPINRef, error) {
	if ref == "" {
		return nil, ErrSOPINNotConfigured
	}
	if ref == xkmssdk.DEFAULT_PASSWORD {
		return nil, &SOPINRefError{Reason: "DEFAULT_PASSWORD makes platformd generate a new SO PIN on every start"}
	}
	if strings.HasPrefix(ref, kmsScheme) {
		return parseKMSSOPINRef(ref)
	}
	if strings.Contains(ref, schemeSeparator) {
		return nil, &SOPINRefError{Reason: "only a literal or a kms://...?ensure=true URI can be resolved at firstboot"}
	}
	return &SOPINRef{Literal: []byte(ref)}, nil
}

// parseKMSSOPINRef splits a kms:// SO PIN URI the way the quicbaas kms://
// resolver does: the path is everything before '?', and the query carries
// the ensure options.
func parseKMSSOPINRef(ref string) (*SOPINRef, error) {
	rest := strings.TrimPrefix(ref, kmsScheme)
	path, rawQuery, _ := strings.Cut(rest, "?")
	if path == "" {
		return nil, &SOPINRefError{Reason: fmt.Sprintf("%s has no secret path", ref)}
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, &SOPINRefError{Reason: fmt.Sprintf("%s has a malformed query string", ref)}
	}
	ensure, err := strconv.ParseBool(query.Get(soPINQueryEnsure))
	if err != nil || !ensure {
		return nil, &SOPINRefError{Reason: fmt.Sprintf("%s must set ensure=true so firstboot can generate it", ref)}
	}
	if query.Get(soPINQueryEncoder) != sopinEncodingNum {
		return nil, &SOPINRefError{Reason: fmt.Sprintf("%s must set enc=numeric", ref)}
	}
	length, err := strconv.Atoi(query.Get(soPINQueryLength))
	if err != nil || length <= 0 {
		return nil, &SOPINRefError{Reason: fmt.Sprintf("%s must set len to a positive integer", ref)}
	}
	return &SOPINRef{KMSPath: path, Length: length}, nil
}

// GenerateNumericSOPIN returns n ASCII digits sampled uniformly from
// crypto/rand, the form the quicbaas kms:// resolver generates for
// enc=numeric.
func GenerateNumericSOPIN(n int) ([]byte, error) {
	if n <= 0 {
		return nil, &SOPINGenerateError{Cause: ErrSOPINLengthInvalid}
	}
	ten := big.NewInt(10)
	pin := make([]byte, n)
	for i := range pin {
		digit, err := rand.Int(entropy, ten)
		if err != nil {
			return nil, &SOPINGenerateError{Cause: err}
		}
		pin[i] = byte('0' + digit.Int64())
	}
	return pin, nil
}
