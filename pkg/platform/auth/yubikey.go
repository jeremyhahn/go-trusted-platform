package auth

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/GeertJohan/yubigo"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

type YubiAuth struct {
	logger *logging.Logger
	client *yubigo.YubiAuth
	PlatformAuthenticator
}

func NewYubiKeyAuthenticator(
	logger *logging.Logger,
	clientID string,
	secretKey keystore.Password) (PlatformAuthenticator, error) {

	var secret string
	var err error

	if secretKey != nil {
		secret, err = secretKey.String()
		if err != nil {
			return nil, err
		}
	}

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

	return &YubiAuth{
		logger: logger,
		client: client,
	}, nil
}

func (yubiauth *YubiAuth) Prompt() []byte {
	fmt.Println("Touch your YubiKey to send an OTP code...")
	fmt.Println()
	return prompt.PasswordPrompt("YubiKey OTP")
}

func (yubiauth *YubiAuth) Authenticate(otp []byte) error {
	result, ok, err := yubiauth.client.Verify(string(otp))
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
	yubiauth.logger.Debugf("yubiauth: result: %s", result)
	return nil
}
