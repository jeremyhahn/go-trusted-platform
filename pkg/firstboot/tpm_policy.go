package firstboot

import (
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmstypes "github.com/jeremyhahn/go-xkms/pkg/types"
)

// tpmPolicyName names the platform TPM policy when platform is set, else none.
func tpmPolicyName(platform bool) string {
	if platform {
		return xkmstypes.TPMPolicyPlatform
	}
	return ""
}

// hasPlatformPolicy reports whether attrs are bound to the platform TPM policy.
func hasPlatformPolicy(attrs *xkmssdk.KeyAttributes) bool {
	return attrs != nil && attrs.TPMPolicy == xkmstypes.TPMPolicyPlatform
}
