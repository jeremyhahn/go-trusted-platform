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

package grpc

//go:generate protoc --go_out=../../../sdk/go/gen --go_opt=paths=source_relative --go-grpc_out=../../../sdk/go/gen --go-grpc_opt=paths=source_relative -I proto proto/common.proto proto/tpm.proto proto/sdn.proto proto/compute.proto proto/daemon.proto proto/ca.proto proto/iam.proto proto/vtpm.proto proto/device.proto proto/platform_dns.proto proto/idevid.proto proto/attestation.proto proto/kms.proto proto/invitation.proto proto/pxe.proto proto/switch.proto proto/ceremony.proto proto/piv.proto proto/luks.proto proto/fido2.proto proto/proxy.proto proto/ntp.proto proto/vpn.proto proto/cache.proto proto/scheduler.proto proto/messaging.proto proto/objectstorage.proto
