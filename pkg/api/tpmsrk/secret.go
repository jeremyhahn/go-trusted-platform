package tpmsrk

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretPassword copies a configured secret into a key password; an unset
// or empty secret yields a nil password.
func secretPassword(sv *xkmstypes.SecretValue) (xkmssdk.Password, error) {
	var password xkmssdk.Password
	if sv == nil {
		return nil, nil
	}
	err := sv.WithBytes(func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		var err error
		password, err = xkmssdk.NewPassword(b)
		return err
	})
	return password, err
}
