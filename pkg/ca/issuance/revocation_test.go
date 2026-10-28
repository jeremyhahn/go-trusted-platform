package issuance

import (
	"errors"
	"testing"
)

func TestValidateRevocationReason_AcceptsEveryCRLReason(t *testing.T) {
	for _, code := range []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 10} {
		if err := ValidateRevocationReason(code); err != nil {
			t.Errorf("reason %d: %v, want nil", code, err)
		}
	}
}

func TestValidateRevocationReason_RefusesAnUndefinedCode(t *testing.T) {
	for _, code := range []int{7, -1, 11, 99} {
		err := ValidateRevocationReason(code)
		var unknown *UnknownRevocationReasonError
		if !errors.As(err, &unknown) {
			t.Fatalf("reason %d: %v, want *UnknownRevocationReasonError", code, err)
		}
		if unknown.Code != code {
			t.Errorf("reason %d: error carries code %d", code, unknown.Code)
		}
		if !IsInvalidRequest(err) {
			t.Errorf("reason %d: IsInvalidRequest = false, want true", code)
		}
	}
}
