//go:build azurecompute

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

package azure

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"golang.org/x/crypto/ssh"
)

// isNotFound reports whether an Azure API error is a "resource not found"
// condition (HTTP 404 / ResourceNotFound).
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode == 404 || respErr.ErrorCode == "ResourceNotFound" {
			return true
		}
	}
	return strings.Contains(err.Error(), "ResourceNotFound") ||
		strings.Contains(err.Error(), "404")
}

// resourceName returns the final path segment of an Azure resource ID
// (e.g. ".../snapshots/backup-1" -> "backup-1"). A value with no slash is
// returned unchanged.
func resourceName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

// generateSSHAuthorizedKey returns a throwaway OpenSSH-format ed25519 public
// key. Azure mandates an OSProfile with an admin credential for image-based VM
// provisioning; the platform reaches instances through its own trust
// mechanisms, not this key, so a per-launch ephemeral key satisfies the API
// contract without persisting any credential.
func generateSSHAuthorizedKey() (string, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), nil
}

// derefStr safely dereferences a *string, returning "" for nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
