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

package installer

import (
	"context"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ukiBuilder implements the UKIBuilder interface
// It wraps the dracut-based UKI builder for Alpine Linux
type ukiBuilder struct {
	logger  *logging.Logger
	builder UKIBuilder
}

// NewUKIBuilderAdapter creates a new UKI builder adapter
// Uses dracut-based builder which has native UKI support
func NewUKIBuilderAdapter(logger *logging.Logger) UKIBuilder {
	return &ukiBuilder{
		logger:  logger,
		builder: NewDracutUKIBuilder(logger), // Use dracut for UKI building
	}
}

// BuildUKI builds a Unified Kernel Image
func (ub *ukiBuilder) BuildUKI(ctx context.Context, config *UKIConfig, output io.Writer) error {
	ub.logger.Info("[UKI] Building Unified Kernel Image")

	// Delegate to the dracut builder
	if err := ub.builder.BuildUKI(ctx, config, output); err != nil {
		return ErrUKIBuild("failed to build UKI", err)
	}

	ub.logger.Info("[UKI] UKI built successfully")
	return nil
}

// SignUKI signs the UKI with Secure Boot keys
func (ub *ukiBuilder) SignUKI(ctx context.Context, ukiPath string, config *SecureBootConfig) error {
	ub.logger.Info("[UKI] Signing UKI with Secure Boot keys")

	// Delegate to the dracut builder
	if err := ub.builder.SignUKI(ctx, ukiPath, config); err != nil {
		return err
	}

	ub.logger.Info("[UKI] UKI signed successfully")
	return nil
}
