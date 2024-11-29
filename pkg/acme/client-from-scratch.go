package acme

// import (
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"net/http"

// 	"github.com/go-jose/go-jose/v4"
// 	"golang.org/x/crypto/acme"

// 	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
// 	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
// )

// var (
// 	ErrRegistrationFailed    = errors.New("ACME registration failed")
// 	ErrOrderCreationFailed   = errors.New("ACME order creation failed")
// 	ErrChallengeResolution   = errors.New("ACME challenge resolution failed")
// 	ErrChallengeFinalization = errors.New("ACME challenge finalization failed")
// 	ErrAuthorizationFailed   = errors.New("Authorization failed")
// )

// type ACMEClient struct {
// 	acmeClient *acme.Client
// 	baseURL    string
// 	accountURL string
// 	orderURL   string
// 	keyring    *platform.Keyring
// 	keyAttrs   *keystore.KeyAttributes
// 	directory  *Directory
// 	jose.NonceSource
// }

// // Creates a new ACME client
// func NewClient(
// 	baseURL string,
// 	client *http.Client,
// 	keyring *platform.Keyring,
// 	keyAttrs *keystore.KeyAttributes) (*ACMEClient, error) {

// 	url := fmt.Sprintf("%s/acme/directory", baseURL)
// 	// directory, err := GetDirectory(url, client)
// 	// if err != nil {
// 	// 	return nil, fmt.Errorf("failed to fetch ACME directory: %v", err)
// 	// }
// 	store, err := keyring.Store(keyAttrs.StoreType.String())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}
// 	signer, err := store.Signer(keyAttrs)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}
// 	acmeClient := &acme.Client{
// 		DirectoryURL: url,
// 		Key:          signer,
// 		HTTPClient:   client,
// 	}
// 	return &ACMEClient{
// 		acmeClient: acmeClient,
// 		baseURL:    baseURL,
// 		// directory:  directory,
// 		keyAttrs: keyAttrs,
// 		keyring:  keyring,
// 	}, nil
// }

// // // FetchNonce fetches a fresh nonce from the ACME server
// // func (acme *ACMEClient) FetchNonce() ([]byte, error) {

// // 	// url := fmt.Sprintf("%s/acme/new-nonce", acme.baseURL)

// // 	req, err := http.NewRequest(http.MethodHead, acme.directory.NewNonce, nil)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to create request: %v", err)
// // 	}

// // 	// Send the request
// // 	resp, err := acme.acmeClient.HTTPClient.Do(req)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to fetch nonce: %v", err)
// // 	}
// // 	defer resp.Body.Close()

// // 	// Check the Replay-Nonce header
// // 	nonce := resp.Header.Get("Replay-Nonce")
// // 	if nonce == "" {
// // 		return nil, fmt.Errorf("nonce not found in ACME server response")
// // 	}

// // 	return []byte(nonce), nil
// // }

// // // GetDirectory fetches the ACME directory from the server and returns the endpoints as a struct.
// // func GetDirectory(directoryURL string, client *http.Client) (*Directory, error) {

// // 	// Send a GET request to the ACME directory URL
// // 	resp, err := client.Get(directoryURL)
// // 	if err != nil {
// // 		return nil, fmt.Errorf("failed to fetch ACME directory: %v", err)
// // 	}
// // 	defer resp.Body.Close()

// // 	// Check for a successful response
// // 	if resp.StatusCode != http.StatusOK {
// // 		return nil, fmt.Errorf("failed to fetch ACME directory: server returned status %d", resp.StatusCode)
// // 	}

// // 	// Parse the response body into the ACMEEndpoints struct
// // 	var endpoints Directory
// // 	decoder := json.NewDecoder(resp.Body)
// // 	if err := decoder.Decode(&endpoints); err != nil {
// // 		return nil, fmt.Errorf("failed to decode ACME directory response: %v", err)
// // 	}

// // 	return &endpoints, nil
// // }

// // Registers a new account with the ACME server
// func (client *ACMEClient) RegisterAccount(email string) (*acme.Account, error) {

// 	account := &acme.Account{
// 		Contact: []string{fmt.Sprintf("mailto:%s", email)},
// 	}

// 	newAccount, err := client.acmeClient.Register(context.Background(), account, acme.AcceptTOS)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return newAccount, nil
// }

// // Creates a new ACME order for the domain
// func (acme *ACMEClient) RequestCertificate(domain string) ([]byte, error) {

// 	url := fmt.Sprintf("%s/acme/new-order", acme.baseURL)

// 	// Order payload
// 	orderPayload := map[string]interface{}{
// 		"identifiers": []map[string]string{
// 			{"type": "dns", "value": domain},
// 		},
// 	}

// 	requestBody, _ := json.Marshal(orderPayload)

// 	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(requestBody))
// 	if err != nil {
// 		return nil, ErrOrderCreationFailed
// 	}

// 	// Set appropriate headers
// 	req.Header.Set("Content-Type", "application/jose+json")

// 	resp, err := acme.acmeClient.HTTPClient.Do(req)
// 	if err != nil {
// 		return nil, ErrOrderCreationFailed
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusCreated {
// 		return nil, ErrOrderCreationFailed
// 	}

// 	// Parse order URL from the response headers or body
// 	acme.orderURL = resp.Header.Get("Location")

// 	// Parse the order URL from the response body
// 	return nil, ErrOrderCreationFailed
// }

// // Retrieves the challenge for the domain
// func (acme *ACMEClient) FetchChallenges() ([]map[string]interface{}, error) {

// 	req, err := http.NewRequest(http.MethodGet, acme.orderURL, nil)
// 	if err != nil {
// 		return nil, ErrAuthorizationFailed
// 	}

// 	resp, err := acme.acmeClient.HTTPClient.Do(req)
// 	if err != nil {
// 		return nil, ErrAuthorizationFailed
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return nil, ErrAuthorizationFailed
// 	}

// 	var responseBody map[string]interface{}
// 	json.NewDecoder(resp.Body).Decode(&responseBody)

// 	// Extract challenges from the response body
// 	authorizations := responseBody["authorizations"].([]interface{})
// 	var challenges []map[string]interface{}
// 	for _, authorization := range authorizations {
// 		auth := authorization.(map[string]interface{})
// 		if challs, ok := auth["challenges"].([]interface{}); ok {
// 			for _, chall := range challs {
// 				challenges = append(challenges, chall.(map[string]interface{}))
// 			}
// 		}
// 	}

// 	return challenges, nil
// }

// // ResolveChallenge resolves a specific ACME challenge
// func (acme *ACMEClient) ResolveChallenge(challenge map[string]interface{}) error {
// 	// Placeholder: Perform the DNS-01, HTTP-01, or device-attest-01 challenge resolution
// 	// Implement this logic depending on the challenge type
// 	fmt.Println("Resolving challenge:", challenge["type"])
// 	return nil
// }

// // finalizes the ACME order after challenge resolution
// func (acme *ACMEClient) FinalizeOrder() error {
// 	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/finalize", acme.orderURL), nil)
// 	if err != nil {
// 		return ErrChallengeFinalization
// 	}

// 	resp, err := acme.acmeClient.HTTPClient.Do(req)
// 	if err != nil {
// 		return ErrChallengeFinalization
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		return ErrChallengeFinalization
// 	}

// 	fmt.Println("Order finalized successfully.")
// 	return nil
// }

// // CreateJWS creates and signs a JWS for a given payload using the appropriate key
// func (acme *ACMEClient) createJWS(payload, nonce []byte, url string, useKID bool) ([]byte, error) {

// 	var alg jose.SignatureAlgorithm

// 	alg, err := parseJOSEAlgorithm(acme.keyAttrs.SignatureAlgorithm.String())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse JOSE signature algorithm: %v", err)
// 	}

// 	store, err := acme.keyring.Store(acme.keyAttrs.StoreType.String())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}

// 	opaqueKey, err := store.Key(acme.keyAttrs)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}

// 	opaqueSigner := NewSigner(acme.keyring.Random(), opaqueKey)

// 	signerOptions := jose.SignerOptions{}
// 	signerOptions.NonceSource = NewNonce(nonce)
// 	signerOptions.EmbedJWK = useKID == false
// 	signerOptions.WithHeader("nonce", nonce)
// 	signerOptions.WithHeader("url", url)

// 	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaqueSigner}, &signerOptions)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create signer: %v", err)
// 	}

// 	jws, err := signer.Sign(payload)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign JWS: %v", err)
// 	}

// 	compactJWS, err := jws.CompactSerialize()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to serialize JWS: %v", err)
// 	}

// 	return []byte(compactJWS), nil
// }
