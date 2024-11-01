package dns01

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
)

func Verify(domain, token, keyAuthorization string) error {

	sha := sha256.Sum256([]byte(keyAuthorization))
	expected := base64.RawURLEncoding.EncodeToString(sha[:])

	txtRecords, err := net.LookupTXT(fmt.Sprintf("_acme-challenge.%s", domain))
	if err != nil {
		return fmt.Errorf("failed to query DNS TXT records: %v", err)
	}

	for _, txt := range txtRecords {
		if txt == expected {
			return nil
		}
	}

	return fmt.Errorf("DNS-01 challenge failed")
}
