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

package kms

import (
	"strings"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// kmsClientFactory builds a quicbaas KMSClient from a BaseCommand. Tests
// override this so the key-lifecycle verbs can be exercised without
// dialing a live daemon.
type kmsClientFactory func(base *cli.BaseCommand) (quicbaassdk.KMSClient, error)

// activeKMSClientFactory is the factory currently in use. The default
// factory dials the daemon via the platform SDK Client.
var activeKMSClientFactory kmsClientFactory = defaultKMSClientFactory

// SetKMSClientFactory installs a new KMS client factory and returns a
// restorer that the caller invokes via defer. Intended for in-process
// tests; production code MUST NOT call this.
func SetKMSClientFactory(f kmsClientFactory) func() {
	prev := activeKMSClientFactory
	activeKMSClientFactory = f
	return func() { activeKMSClientFactory = prev }
}

// defaultKMSClientFactory dials the daemon via the platform SDK Client
// and returns the KMSClient from the QuicBaaS Security service.
func defaultKMSClientFactory(base *cli.BaseCommand) (quicbaassdk.KMSClient, error) {
	q, err := base.Client().QuicBaaS()
	if err != nil {
		return nil, err
	}
	return q.Security().KMS(), nil
}

// openKMSClient is the convenience wrapper used by verb handlers to
// acquire a KMS client. It delegates to the active factory so tests can
// swap it out atomically.
func openKMSClient(base *cli.BaseCommand) (quicbaassdk.KMSClient, error) {
	return activeKMSClientFactory(base)
}

// dekClientFactory opens the SDK DEK client for a `kms dek` verb.
type dekClientFactory func(base *cli.BaseCommand) (quicbaassdk.DEKClient, error)

var activeDEKClientFactory dekClientFactory = defaultDEKClientFactory

// SetDEKClientFactory replaces the DEK client factory and returns a function
// that restores the previous one.
func SetDEKClientFactory(f dekClientFactory) func() {
	prev := activeDEKClientFactory
	activeDEKClientFactory = f
	return func() { activeDEKClientFactory = prev }
}

func defaultDEKClientFactory(base *cli.BaseCommand) (quicbaassdk.DEKClient, error) {
	q, err := base.Client().QuicBaaS()
	if err != nil {
		return nil, err
	}
	return q.Security().DEK(), nil
}

func openDEKClient(base *cli.BaseCommand) (quicbaassdk.DEKClient, error) {
	return activeDEKClientFactory(base)
}

// secretsClientFactory opens the SDK secrets client for a `kms secrets` verb.
type secretsClientFactory func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error)

var activeSecretsClientFactory secretsClientFactory = defaultSecretsClientFactory

// SetSecretsClientFactory replaces the secrets client factory and returns a
// function that restores the previous one.
func SetSecretsClientFactory(f secretsClientFactory) func() {
	prev := activeSecretsClientFactory
	activeSecretsClientFactory = f
	return func() { activeSecretsClientFactory = prev }
}

func defaultSecretsClientFactory(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
	q, err := base.Client().QuicBaaS()
	if err != nil {
		return nil, err
	}
	return q.Security().Secrets(), nil
}

func openSecretsClient(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
	return activeSecretsClientFactory(base)
}

// parseSDKKeyUsage converts a CLI usage string to the SDK KeyUsage.
func parseSDKKeyUsage(usage string) (kms.KeyUsage, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(usage), "-", "_"))
	switch normalized {
	case "encrypt":
		return kms.KeyUsageEncrypt, nil
	case "decrypt":
		return kms.KeyUsageDecrypt, nil
	case "sign":
		return kms.KeyUsageSign, nil
	case "verify":
		return kms.KeyUsageVerify, nil
	case "wrap", "wrap_key":
		return kms.KeyUsageWrap, nil
	case "unwrap", "unwrap_key":
		return kms.KeyUsageUnwrap, nil
	default:
		return 0, ErrInvalidKeyUsage{Usage: usage}
	}
}

// parseSDKKeyUsages converts CLI usage strings to SDK KeyUsage values.
func parseSDKKeyUsages(usages []string) ([]kms.KeyUsage, error) {
	result := make([]kms.KeyUsage, 0, len(usages))
	for _, u := range usages {
		usage, err := parseSDKKeyUsage(u)
		if err != nil {
			return nil, err
		}
		result = append(result, usage)
	}
	return result, nil
}

// keyUsageStrings renders SDK KeyUsage values as strings.
func keyUsageStrings(usages []kms.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		result = append(result, u.String())
	}
	return result
}

// parseTagPairs parses key=value tag pairs into a map.
func parseTagPairs(tags []string) (map[string]string, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, value, found := strings.Cut(tag, "=")
		if !found || key == "" {
			return nil, ErrInvalidTagFormat{Tag: tag}
		}
		result[key] = value
	}
	return result, nil
}
