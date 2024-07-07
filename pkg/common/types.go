package common

import "errors"

var (
	ErrPasswordsDontMatch = errors.New("trusted-platform: passwords don't match")
	ErrPasswordComplexity = errors.New("trusted-platform: password doesn't meet complexity requirements")
)
