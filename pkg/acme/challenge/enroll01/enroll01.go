package enroll01

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

// The enroll-01 challenge is a custom, modified version of the http-01 challenge
// that facilitates OEM enrollment of new devices during manufacturer provisioning
// time using the procedures outlined in section 6 - Identity Provisioning - in the
// TCG TPM 2.0 Keys for Device Identity and Attestation documentation.
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_DevID_v1r2_02dec2020.pdf

// This challenge specifically supports the procedures in section 6.2 - OEM Installation
// of IAK and IDevID in a Single Pass, using the Included Attestation Variation documented
// in section 6.1.4.

// The enroll-01 challenge is a two-step process:
// 1. The server performs an HTTP GET request to /.well-known/acme-challenge/<token> to receive
// the TCG-CSR-IDEVID.
// 2. The server verifies the CSR and generates a secret credential using TPM2_MakeCredential. The
// credential is sent via HTTP POST to /.well-known/acme-activation/<token> for activation.

const (
	secretPath    = "/.well-known/acme-activation/"
	challengePath = "/.well-known/acme-challenge/"
)

var (
	server                *http.Server
	shutdownOnce          sync.Once
	challengeDone         chan struct{}
	serverShutdownTimeout = 5 * time.Second
)

type activateCredentialRequest struct {
	CredentialBlob  string `json:"credentialBlob"`
	EncryptedSecret string `json:"encryptedSecret"`
}

// Verifies the enroll-01 challenge by performing an HTTP request to
// the /.well-known/acme-challenge/<token> endpoint to receive the TCG-CSR-IDEVID.
// The TCG-CSR-IDEVID is then verified by the Certificate Authority and a new secret
// credential is created using TPM2_MakeCredential. The credential is sent to the client
// at /.well-known/acme-activation/<token> for activation using TPM2_ActivateCredential.
// Upon returning a 200 OK status code and decrypted secret credential, the challenge
// is complete and the enroll-01 HTTP challenge service is shutdown. Upon successful
// completion of this challenge, the client has verified that it is in possession of
// the private keys used in the request and that the keys reside in an authentic TPM.
func Verify(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	domain, port, token, keyAuth string) error {

	// Retrieve the TCG-CSR-IDevID from the challenge endpoint
	endpoint := fmt.Sprintf("http://%s:%s%s%s", domain, port, challengePath, token)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 5 * time.Second,
				Resolver:  resolver,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// Disable HTTPS verification for HTTP-01
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Decode the packed TCG-CSR-IDevID
	packedCSR, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return err
	}

	// Verify the TCG-CSR-IDevID and get back the credential blob, encrypted secret,
	// and raw plain-text secret for comparison with the decrypted secret returned
	// from the client.
	credentialBlob, encryptedSecret, secret, err := ca.VerifyTCG_CSR_IDevIDBytes(
		packedCSR, ca.DefaultSignatureAlgorithm())
	if err != nil {
		return err
	}

	// Send the encrypted credential to the client for activation
	secretEndpoint := fmt.Sprintf("http://%s:%s%s%s", domain, port, secretPath, token)

	activationRequest := &activateCredentialRequest{
		CredentialBlob:  base64.RawURLEncoding.EncodeToString(credentialBlob),
		EncryptedSecret: base64.RawURLEncoding.EncodeToString(encryptedSecret),
	}

	jsonData, err := json.Marshal(activationRequest)
	if err != nil {
		return err
	}

	resp, err = client.Post(secretEndpoint, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if bytes.Compare(body, secret) != 0 {
		return fmt.Errorf("invalid credential activation")
	}

	return nil
}

// Setup initializes the enroll-01 challenge by creating the key authorization and placing it
// as the TCG-CSR-IDEVID qualifying data during key certification, and starts a new HTTP server
// with the required challenge handlers.
func Setup(
	port, keyAuth string,
	ca ca.CertificateAuthority,
	tpm tpm2.TrustedPlatformModule) ([]byte, error) {

	challengeDone = make(chan struct{})

	ekCert, err := tpm.EKCertificate()
	if err != nil {
		return nil, err
	}

	akAttrs, err := tpm.IAKAttributes()
	if err != nil {
		return nil, err
	}

	_, tcgCSR, err := tpm.CreateIDevID(akAttrs, ekCert, []byte(keyAuth))
	if err != nil {
		return nil, err
	}

	packedCSR, err := tpm2.PackIDevIDCSR(tcgCSR)
	if err != nil {
		return nil, err
	}

	startServer(port, tpm, packedCSR)

	return packedCSR, nil
}

// startServer initializes the HTTP server and starts listening for incoming requests.
func startServer(port string, tpm tpm2.TrustedPlatformModule, packedCSR []byte) {

	// Set up HTTP server to handle challenges
	mux := http.NewServeMux()
	mux.HandleFunc(challengePath, challengeHandlerHTTPx(packedCSR))
	mux.HandleFunc(secretPath, activateCredentialHandler(tpm))

	addr := fmt.Sprintf(":%s", port)

	server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		// ErrorLog:     customLogger, // Optionally set a custom logger
	}

	// Start the HTTP server in a separate goroutine
	go func() {
		log.Printf("Starting HTTP server on %s", addr)
		// Listen on all interfaces
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", addr, err)
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Handle graceful shutdown on interrupt signals
	go handleShutdown()
}

// encryptedSecretHandler returns the decrypted credential by performing TPM2_ActivateCredential
func activateCredentialHandler(
	tpm tpm2.TrustedPlatformModule) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Extract the token from the URL path
		token := r.URL.Path[len(challengePath):]
		if token == "" {
			http.Error(w, "Token not provided", http.StatusBadRequest)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
			return
		}

		// Ensure the Content-Type is application/json.
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}

		// Read the request body.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			log.Printf("Error reading request body: %v", err)
			return
		}
		defer r.Body.Close()

		// Limit the size of the request body to prevent abuse.
		const maxBodySize = 1048576 // 1MB
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		// Unmarshal the JSON into the Payload struct.
		var activationRequest activateCredentialRequest
		if err := json.Unmarshal(body, &activationRequest); err != nil {
			http.Error(w, "Invalid activation request", http.StatusBadRequest)
			log.Printf("JSON unmarshal error: %v", err)
			return
		}

		credentialBlob, err := base64.RawURLEncoding.DecodeString(activationRequest.CredentialBlob)
		if err != nil {
			http.Error(w, "Invalid credential blob", http.StatusBadRequest)
			log.Printf("Failed to decode credential blob: %v", err)
			return
		}

		encryptedSecret, err := base64.RawURLEncoding.DecodeString(activationRequest.EncryptedSecret)
		if err != nil {
			http.Error(w, "Invalid encrypted secret", http.StatusBadRequest)
			log.Printf("Failed to decode encrypted secret: %v", err)
			return
		}

		secret, err := tpm.ActivateCredential(credentialBlob, encryptedSecret)
		if err != nil {
			http.Error(w, "Failed to activate credential", http.StatusInternalServerError)
			log.Printf("Failed to activate credential: %v", err)
			return
		}

		// Serve the key authorization
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(secret)
		if err != nil {
			log.Printf("Failed to write response for token %s: %v", token, err)
			return
		}

		// Initiate server shutdown
		go shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				log.Fatalf("Server shutdown failed: %v", err)
			}
		})
	}
}

// challengeHandlerHTTPx returns an HTTP handler function that serves the key authorization.
func challengeHandlerHTTPx(packedCSR []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the token from the URL path
		token := r.URL.Path[len(challengePath):]
		if token == "" {
			http.Error(w, "Token not provided", http.StatusBadRequest)
			return
		}

		encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)

		// Serve the key authorization
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(encodedCSR))
		if err != nil {
			log.Printf("Failed to write response for token %s: %v", token, err)
			return
		}
	}
}

// handleShutdown listens for OS interrupt signals and gracefully shuts down the server.
func handleShutdown() {
	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-sigChan
	log.Printf("Received signal: %v. Initiating shutdown...", sig)

	// Initiate server shutdown
	shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Server shutdown failed: %v", err)
		}
	})
}
