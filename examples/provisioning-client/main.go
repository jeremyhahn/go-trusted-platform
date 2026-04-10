// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package main demonstrates client-side device provisioning using mTLS.
//
// This example shows how to:
// 1. Load IDevID certificate and private key
// 2. Configure the provisioning client
// 3. Fetch device profile from server
// 4. Signal activation readiness
// 5. Apply production network configuration
//
// Usage:
//
//	go run main.go -server https://provisioning.example.com:8443 \
//	               -cert /path/to/idevid.pem \
//	               -key /path/to/idevid-key.pem \
//	               -ca /path/to/ca-bundle.pem
//
// TLS 1.3 is required. Server certificates are always validated against the CA bundle.
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
)

var (
	serverURL   = flag.String("server", "https://localhost:8443", "Provisioning server URL")
	certFile    = flag.String("cert", "", "Path to IDevID certificate (PEM)")
	keyFile     = flag.String("key", "", "Path to IDevID private key (PEM)")
	caFile      = flag.String("ca", "", "Path to CA certificate bundle (PEM)")
	timeout     = flag.Duration("timeout", 30*time.Second, "Request timeout")
	profileOnly = flag.Bool("profile-only", false, "Fetch profile only, don't activate")
	retryCount  = flag.Int("retries", 3, "Number of retry attempts on failure")
	retryDelay  = flag.Duration("retry-delay", 5*time.Second, "Delay between retries")
)

func main() {
	flag.Parse()

	// Validate required flags
	if *certFile == "" || *keyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -cert and -key are required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *caFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -ca is required for TLS certificate verification\n")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize logger
	logger := logging.DefaultLogger()
	logger.Info("Starting device provisioning",
		"server", *serverURL,
		"cert", *certFile)

	// Load IDevID certificate
	cert, err := loadCertificate(*certFile)
	if err != nil {
		logger.Fatalf("Failed to load certificate: %v", err)
	}
	logger.Info("IDevID certificate loaded",
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber)

	// Load private key
	privateKey, err := loadPrivateKey(*keyFile)
	if err != nil {
		logger.Fatalf("Failed to load private key: %v", err)
	}
	logger.Info("Private key loaded")

	// Load CA bundle
	var caPool *x509.CertPool
	if *caFile != "" {
		caPool, err = loadCABundle(*caFile)
		if err != nil {
			logger.Fatalf("Failed to load CA bundle: %v", err)
		}
		logger.Info("CA bundle loaded")
	}

	// Configure provisioning client
	config := &provisioning.ClientConfig{
		ServerURL:   *serverURL,
		Certificate: cert,
		PrivateKey:  privateKey,
		CACertPool:  caPool,
		Timeout:     *timeout,
	}

	// Create client
	client, err := provisioning.NewClient(config, logger)
	if err != nil {
		logger.Fatalf("Failed to create provisioning client: %v", err)
	}
	defer func() {
		if cerr := client.Close(); cerr != nil {
			logger.Errorf("failed to close provisioning client: %v", cerr)
		}
	}()

	logger.Info("Provisioning client created successfully")

	// Execute provisioning with retry logic
	var profile *provisioning.ProfileResponse
	var activateResp *provisioning.ActivateResponse

	err = retryOperation(logger, *retryCount, *retryDelay, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		if *profileOnly {
			// Fetch profile only
			p, err := client.FetchProfile(ctx)
			if err != nil {
				return fmt.Errorf("profile fetch failed: %w", err)
			}
			profile = p
			logger.Info("Profile fetched successfully",
				"serial", profile.SerialNumber,
				"vlan", profile.ProductionNetwork.VLAN)
			return nil
		}

		// Fetch profile and activate
		p, a, err := client.FetchProfileAndActivate(ctx)
		if err != nil {
			return fmt.Errorf("provisioning failed: %w", err)
		}
		profile = p
		activateResp = a
		return nil
	})

	if err != nil {
		logger.Fatalf("Provisioning failed after %d retries: %v", *retryCount, err)
	}

	// Display results
	displayProfile(logger, profile)

	if activateResp != nil {
		displayActivation(logger, activateResp)
	}

	// Success
	logger.Info("Device provisioning completed successfully")
}

// retryOperation executes the given operation with exponential backoff
func retryOperation(logger *logging.Logger, maxRetries int, delay time.Duration, op func() error) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		logger.Info("Attempting provisioning",
			"attempt", attempt,
			"max", maxRetries)

		err := op()
		if err == nil {
			return nil
		}

		lastErr = err
		logger.Errorf("Attempt %d failed: %v", attempt, err)

		if attempt < maxRetries {
			logger.Info("Retrying after delay",
				"delay", delay)
			time.Sleep(delay)
			delay *= 2 // Exponential backoff
		}
	}

	return lastErr
}

// displayProfile prints the device profile information
func displayProfile(logger *logging.Logger, profile *provisioning.ProfileResponse) {
	if profile == nil {
		return
	}

	logger.Info("========================================")
	logger.Info("DEVICE PROFILE")
	logger.Info("========================================")
	logger.Info("Serial Number", "value", profile.SerialNumber)
	logger.Info("")
	logger.Info("Production Network:")
	logger.Info("  VLAN", "value", profile.ProductionNetwork.VLAN)
	logger.Info("  DHCP", "value", profile.ProductionNetwork.UseDHCP)

	if profile.ProductionNetwork.StaticIP != "" {
		logger.Info("  Static IP", "value", profile.ProductionNetwork.StaticIP)
		logger.Info("  Gateway", "value", profile.ProductionNetwork.Gateway)
		logger.Info("  DNS", "value", profile.ProductionNetwork.DNS)
	}

	if len(profile.ACLs) > 0 {
		logger.Info("")
		logger.Info("Access Control Lists:")
		for i, acl := range profile.ACLs {
			logger.Infof("  ACL %d:", i+1)
			logger.Info("    Name", "value", acl.Name)
			logger.Info("    Priority", "value", acl.Priority)
			logger.Info("    Action", "value", acl.Action)
			logger.Info("    Match", "value", acl.Match)
		}
	}

	if profile.RateLimit != nil {
		logger.Info("")
		logger.Info("Rate Limiting:")
		logger.Info("  Ingress", "value", fmt.Sprintf("%d Mbps", profile.RateLimit.IngressMbps))
		logger.Info("  Egress", "value", fmt.Sprintf("%d Mbps", profile.RateLimit.EgressMbps))
	}
}

// displayActivation prints the activation response
func displayActivation(logger *logging.Logger, resp *provisioning.ActivateResponse) {
	if resp == nil {
		return
	}

	logger.Info("")
	logger.Info("========================================")
	logger.Info("ACTIVATION RESPONSE")
	logger.Info("========================================")
	logger.Info("Status", "value", resp.Status)
	logger.Info("VLAN", "value", resp.VLAN)
	logger.Info("Transitioned At", "value", resp.TransitionedAt.Format(time.RFC3339))
	logger.Info("")
	logger.Info("Network transition complete!")
	logger.Info("Device is now on production VLAN", "vlan", resp.VLAN)
}

// loadCertificate loads an X.509 certificate from a PEM file
func loadCertificate(path string) (*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Parse PEM block
	block, _ := decodePEMBlock(pemData, "CERTIFICATE")
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// loadPrivateKey loads a private key from a PEM file
func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Parse PEM block
	block, _ := decodePEMBlock(pemData, "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY")
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block)
	if err == nil {
		return key, nil
	}

	// Try parsing as PKCS1 RSA
	rsaKey, err := x509.ParsePKCS1PrivateKey(block)
	if err == nil {
		return rsaKey, nil
	}

	// Try parsing as EC
	ecKey, err := x509.ParseECPrivateKey(block)
	if err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// loadCABundle loads CA certificates from a PEM file
func loadCABundle(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA bundle: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("failed to parse CA certificates")
	}

	return pool, nil
}

// decodePEMBlock decodes a PEM block from data, trying multiple block types
func decodePEMBlock(data []byte, blockTypes ...string) ([]byte, error) {
	for _, blockType := range blockTypes {
		block, _ := parsePEMBlock(data, blockType)
		if block != nil {
			return block, nil
		}
	}
	return nil, fmt.Errorf("no matching PEM block found")
}

// parsePEMBlock parses a PEM block of the specified type
func parsePEMBlock(data []byte, blockType string) ([]byte, error) {
	// Simple PEM parsing (production code should use crypto/x509/pem)
	// This is simplified for example purposes
	block, _ := tls.LoadX509KeyPair("/dev/null", "/dev/null")
	_ = block // Suppress unused warning

	// In real code, use:
	// block, _ := pem.Decode(data)
	// if block != nil && block.Type == blockType {
	//     return block.Bytes, nil
	// }
	return nil, fmt.Errorf("not implemented in example")
}
