package agent

import (
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
)

// mustSecret wraps a literal test credential in a SecretValue.
func mustSecret(s string) *xkmstypes.SecretValue {
	sv, err := xkmstypes.NewLiteralSecretValue([]byte(s))
	if err != nil {
		panic(err)
	}
	return sv
}
