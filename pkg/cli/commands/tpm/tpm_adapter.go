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

package tpm

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TPMBaseCommandInterface defines the interface for TPM service commands.
// This interface is shared across multiple TPM command files (info, clear,
// provision, ek, srk, nvram, seal, unseal, eventlog) that have already
// been migrated to use SDK domain types internally but still require
// the raw gRPC client accessor for SDK client construction.
type TPMBaseCommandInterface interface {
	TPMClient() platformv1.TPMServiceClient
	Printer() *cli.Printer
	Context() context.Context
	Close() error
	Flags() *cli.CommonFlags
}

// tpmBaseCommandAdapter wraps cli.BaseCommand to implement TPMBaseCommandInterface.
type tpmBaseCommandAdapter struct {
	base *cli.BaseCommand
}

func (b *tpmBaseCommandAdapter) TPMClient() platformv1.TPMServiceClient {
	return b.base.Client().TPM()
}

func (b *tpmBaseCommandAdapter) Printer() *cli.Printer {
	return b.base.Printer()
}

func (b *tpmBaseCommandAdapter) Context() context.Context {
	return b.base.Context()
}

func (b *tpmBaseCommandAdapter) Close() error {
	return b.base.Close()
}

func (b *tpmBaseCommandAdapter) Flags() *cli.CommonFlags {
	return b.base.Flags()
}
