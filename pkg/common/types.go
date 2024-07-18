package common

import (
	"errors"
)

var (
	ErrPasswordsDontMatch = errors.New("trusted-platform: passwords don't match")
	ErrPasswordComplexity = errors.New("trusted-platform: password doesn't meet complexity requirements")
	ErrCorruptWrite       = errors.New("certificate-authority: corrupt write: bytes written does not match data length")
)
