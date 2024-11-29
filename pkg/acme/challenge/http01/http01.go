package http01

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	wellKnownChallengePath = "/.well-known/acme-challenge/"
)

var (
	server                *http.Server
	shutdownOnce          sync.Once
	challengeDone         chan struct{}
	serverShutdownTimeout = 15 * time.Second
)

// Verifies an http-01 challenge on the specified port by sending a GET request
// to the challenge URL and ensuring the key authorization presented matches
// the expected value.
// Implements acme.ChallengeVerifierFunc
func Verify(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	url := fmt.Sprintf("http://%s:%s%s%s", domain, port, wellKnownChallengePath, challengeToken)

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
			// Disable HTTPS verification for HTTP requests
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected HTTP status for domain %s: %s", domain, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if strings.TrimSpace(string(body)) != expectedKeyAuth {
		return fmt.Errorf("Key authorization mismatch for domain %s", domain)
	}

	return nil
}

// Sets up a new httpx challenge by starting an HTTP server to handle http-01 challenges
// on the port number specified in the challenge type. For example, httpx-8080 serves the
// http-01 challenge on port 8080.
func Setup(port, keyAuth string) {

	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownChallengePath, challengeHandlerHTTPx(keyAuth))

	logging.DefaultLogger().Info("Setting up http-01 challenge", slog.String("port", port))

	server = &http.Server{
		Addr:         port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", port, err)
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

func Shutdown() {
	logging.DefaultLogger().Info("Shutting down HTTP challenge server")
	shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Server shutdown failed: %v", err)
		}
	})
}

// challengeHandlerHTTPx returns an HTTP handler function that serves the key authorization
// for http-01 challenges using the port number specified in the ACME section of the platform
// configuration file.
func challengeHandlerHTTPx(keyAuth string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		logger := logging.DefaultLogger()

		// Serve the key authorization
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(keyAuth))
		if err != nil {
			logger.Errorf("Failed to write response for key authorization %s: %v", keyAuth, err)
			return
		}

		logging.DefaultLogger().Debug("Served key authorization",
			slog.String("key-authorization", keyAuth),
			slog.String("remote-addr", r.RemoteAddr),
			slog.String("request-uri", r.RequestURI),
			slog.String("http-method", r.Method),
			slog.String("host-header", r.Header.Get("HOST")),
		)
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
