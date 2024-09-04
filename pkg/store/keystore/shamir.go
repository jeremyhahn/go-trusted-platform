package keystore

import "github.com/SSSaaS/sssa-golang"

// Returns a secret split into shares using the Shamir Secret Sharing algorithm.
// Required is the number of shares required to re-create the secret. Shares is
// the number of shards the secret is split into.
func ShareSecret(required int, secret []byte, shares int) ([]string, error) {
	return sssa.Create(required, shares, string(secret))
}

// Returns secret combined from shares split using Shamir's Secret
// Sharing algorithm
func SecretFromShares(shares []string) (string, error) {
	return sssa.Combine(shares)
}
