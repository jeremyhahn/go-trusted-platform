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

package auth

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/GeertJohan/yubigo"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
)

// YubiKeyVerifier defines the interface for YubiKey OTP verification
type YubiKeyVerifier interface {
	Verify(otp string) (*yubigo.YubiResponse, bool, error)
}

// Prompter defines the interface for prompting users
type Prompter interface {
	PasswordPrompt(message string) ([]byte, error)
}

// defaultPrompter implements Prompter using the prompt package
type defaultPrompter struct {
	prompter *prompt.Prompter
}

// PasswordPrompt reads a password without echoing. It delegates to a
// prompt.Prompter rather than the package-level convenience wrapper,
// which calls log.Fatal on a read error and would take the process down
// instead of letting the caller decide.
func (p *defaultPrompter) PasswordPrompt(message string) ([]byte, error) {
	if p.prompter == nil {
		p.prompter = prompt.NewPrompter()
	}
	return p.prompter.PasswordPrompt(message)
}

// yubigoVerifier wraps the yubigo.YubiAuth client
type yubigoVerifier struct {
	client *yubigo.YubiAuth
}

func (v *yubigoVerifier) Verify(otp string) (*yubigo.YubiResponse, bool, error) {
	return v.client.Verify(otp)
}

// YubiAuth provides YubiKey OTP authentication
type YubiAuth struct {
	logger   *logging.Logger
	verifier YubiKeyVerifier
	prompter Prompter
	PlatformAuthenticator
}

// YubiAuthOption is a functional option for configuring YubiAuth
type YubiAuthOption func(*YubiAuth)

// WithVerifier sets a custom verifier for testing
func WithVerifier(verifier YubiKeyVerifier) YubiAuthOption {
	return func(y *YubiAuth) {
		y.verifier = verifier
	}
}

// WithPrompter sets a custom prompter for testing
func WithPrompter(prompter Prompter) YubiAuthOption {
	return func(y *YubiAuth) {
		y.prompter = prompter
	}
}

// NewYubiKeyAuthenticator creates a new YubiKey authenticator
func NewYubiKeyAuthenticator(
	logger *logging.Logger,
	clientID string,
	secretKey xkmssdk.Password,
	opts ...YubiAuthOption) (PlatformAuthenticator, error) {

	var secret string
	var err error

	if secretKey != nil {
		secret, err = secretKey.String()
		if err != nil {
			return nil, err
		}
	}

	yubiAuth := &YubiAuth{
		logger:   logger,
		prompter: &defaultPrompter{},
	}

	// Apply options before creating the default verifier
	for _, opt := range opts {
		opt(yubiAuth)
	}

	// Only create the yubigo client if no custom verifier was provided
	if yubiAuth.verifier == nil {
		yubigo.HTTPClient = &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				MaxConnsPerHost:     20,
				MaxIdleConnsPerHost: 5,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 60 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		client, err := yubigo.NewYubiAuth(clientID, secret)
		if err != nil {
			return nil, err
		}

		yubiAuth.verifier = &yubigoVerifier{client: client}
	}

	return yubiAuth, nil
}

// Prompt displays a YubiKey OTP prompt and reads the OTP from stdin
func (yubiauth *YubiAuth) Prompt() ([]byte, error) {
	fmt.Println("Touch your YubiKey to send an OTP code...")
	fmt.Println()
	return yubiauth.prompter.PasswordPrompt("YubiKey OTP")
}

// Authenticate verifies a YubiKey OTP against the Yubico verification service
func (yubiauth *YubiAuth) Authenticate(otp []byte) error {
	if len(otp) < 32 {
		yubiauth.logger.Error(ErrInvalidOTPLength)
		return ErrInvalidOTPLength
	}

	result, ok, err := yubiauth.verifier.Verify(string(otp))
	if err != nil {
		yubiauth.logger.Error(err)
		return err
	}
	if !ok {
		yubiauth.logger.Error(ErrAuthenticationFailed)
		return ErrAuthenticationFailed
	}
	tokenID := string(otp[:len(otp)-32])
	yubiauth.logger.Debugf("yubiauth: id: %s", tokenID)
	yubiauth.logger.Debugf("yubiauth: result: %+v", result)
	return nil
}
