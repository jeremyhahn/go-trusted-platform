package issuance

// revocationReasons are the RFC 5280 §5.3.1 CRLReason codes. Code 7 is
// unassigned. The platform RevocationReason enum carries the same values.
var revocationReasons = map[int]struct{}{
	0:  {}, // unspecified
	1:  {}, // keyCompromise
	2:  {}, // cACompromise
	3:  {}, // affiliationChanged
	4:  {}, // superseded
	5:  {}, // cessationOfOperation
	6:  {}, // certificateHold
	8:  {}, // removeFromCRL
	9:  {}, // privilegeWithdrawn
	10: {}, // aACompromise
}

// ValidateRevocationReason refuses a reason that is not an RFC 5280 §5.3.1
// CRLReason code. Every revoke entry point calls it before the CA: the CA
// records the reason as given and publishes it in the CRL, so an undefined
// code would reach relying parties as one they cannot read.
func ValidateRevocationReason(code int) error {
	if _, ok := revocationReasons[code]; !ok {
		return &UnknownRevocationReasonError{Code: code}
	}
	return nil
}
