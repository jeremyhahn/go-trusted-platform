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

// The go-xkms tpm2 package uses an internal logging.Logger type
// that cannot be imported from external packages due to Go's internal
// package restrictions.
//
// Fortunately, the tpm2.NewTPM2 function accepts nil for the Logger
// field and will create a default logger internally. This is the
// simplest and most maintainable solution as it avoids import restrictions
// and ensures the TPM2 module uses its own internal logging consistently.
//
// From go-xkms/pkg/tpm2/tpm.go:
//   // Create default logger if none provided
//   if params.Logger == nil {
//       params.Logger = logging.DefaultLogger()
//   }
