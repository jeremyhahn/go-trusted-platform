package iam

import (
	"strings"

	qberrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errPolicySimulationUnimplemented is the reason a REST policy test gives
// when the IAM transport cannot dispatch quicbaas.IAM.Policy/Simulate (the
// pinned embedded transport does not, an upstream go-quicbaas gap).
const errPolicySimulationUnimplemented = "policy simulation is not implemented by the IAM service"

// simulateError maps the upstream's unknown-method or not-implemented error
// for Policy.Simulate to codes.Unimplemented, so the REST layer answers 501
// instead of 500. Any other error is returned unchanged.
func simulateError(err error) error {
	if err == nil {
		return nil
	}
	unimplemented := qberrors.IsUnimplemented(err)
	if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
		unimplemented = true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unknown method") || strings.Contains(msg, "not implemented") || strings.Contains(msg, "unimplemented") {
		unimplemented = true
	}
	if !unimplemented {
		return err
	}
	return status.Errorf(codes.Unimplemented, "%s: %v", errPolicySimulationUnimplemented, err)
}
