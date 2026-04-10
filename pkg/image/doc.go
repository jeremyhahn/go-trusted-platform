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

// Package image provides OCI container image signing and verification capabilities
// for go-trusted-platform. It integrates with the Platform CA for key management
// and supports storing signatures as OCI artifacts alongside container images.
//
// The package supports multiple signature formats including cosign, sigstore, and
// notation, and provides both RSA and ECDSA signature algorithms.
//
// Key features:
//   - Sign OCI container images using Platform CA private keys
//   - Verify image signatures using Platform CA certificate chain
//   - Store and retrieve signatures as OCI artifacts
//   - Support for both RSA and ECDSA signatures
//   - Certificate chain validation
//   - Signature caching for performance
//   - Thread-safe registry client with connection pooling
//
// Example usage:
//
//	// Create a verifier with trust anchors
//	verifier, err := image.NewVerifier(&image.VerifierOptions{
//	    TrustAnchors: []*x509.Certificate{rootCA, intermediateCA},
//	})
//
//	// Verify an image
//	ref, _ := image.ParseReference("registry.example.com/app:v1.0.0")
//	result, err := verifier.VerifyImage(ctx, ref, &image.VerificationOptions{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Verified {
//	    fmt.Printf("Image signed by: %s\n", result.SignerIdentity)
//	}
package image
