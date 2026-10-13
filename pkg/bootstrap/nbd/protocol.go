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

// Package nbd is the boot server's NBD-over-TLS export server for
// diskless-nbd nodes (#689). A node attaches its root as a block device
// exported over the NBD fixed-newstyle protocol; TLS is mandatory, the
// client authenticates with its IDevID certificate verified against the
// platform anchor, and the export is chosen by that verified identity
// alone. The design is in docs/bootstrap/architecture.md and the
// contract in docs/bootstrap/engineering.md §2.
//
// The wire constants below are the NBD protocol's, from the upstream
// specification (doc/proto.md in the nbd project).
package nbd

// BootModel is the bootstrap.yaml boot_model value for a node whose root
// is an NBD export of this server.
const BootModel = "diskless-nbd"

// DefaultPort is the IANA-assigned NBD port.
const DefaultPort = 10809

// Handshake magics.
const (
	nbdMagic         uint64 = 0x4e42444d41474943 // "NBDMAGIC"
	optionMagic      uint64 = 0x49484156454f5054 // "IHAVEOPT"
	optionReplyMagic uint64 = 0x0003e889045565a9
)

// Server handshake flags.
const (
	flagFixedNewstyle uint16 = 1 << 0
	flagNoZeroes      uint16 = 1 << 1
)

// Client handshake flags.
const (
	clientFlagFixedNewstyle uint32 = 1 << 0
	clientFlagNoZeroes      uint32 = 1 << 1
	clientFlagsKnown               = clientFlagFixedNewstyle | clientFlagNoZeroes
)

// Options.
const (
	optExportName uint32 = 1
	optAbort      uint32 = 2
	optStartTLS   uint32 = 5
	optInfo       uint32 = 6
	optGo         uint32 = 7
)

// Option reply types. Errors carry bit 31.
const (
	repAck         uint32 = 1
	repInfo        uint32 = 3
	repFlagError   uint32 = 1 << 31
	repErrUnsup           = repFlagError | 1
	repErrPolicy          = repFlagError | 2
	repErrInvalid         = repFlagError | 3
	repErrPlatform        = repFlagError | 4
	repErrTLSReqd         = repFlagError | 5
)

// Information types in an NBD_REP_INFO reply.
const (
	infoExport    uint16 = 0
	infoName      uint16 = 1
	infoBlockSize uint16 = 3
)

// Transmission flags advertised for every export.
const (
	transHasFlags  uint16 = 1 << 0
	transSendFlush uint16 = 1 << 2
	transSendFUA   uint16 = 1 << 3
	transSendTrim  uint16 = 1 << 5

	exportFlags = transHasFlags | transSendFlush | transSendFUA | transSendTrim
)

// Transmission-phase magics.
const (
	requestMagic     uint32 = 0x25609513
	simpleReplyMagic uint32 = 0x67446698
)

// Commands.
const (
	cmdRead  uint16 = 0
	cmdWrite uint16 = 1
	cmdDisc  uint16 = 2
	cmdFlush uint16 = 3
	cmdTrim  uint16 = 4
)

// Command flags.
const (
	cmdFlagFUA uint16 = 1 << 0
)

// Error codes in a simple reply (Linux errno values, per the spec).
const (
	errNone  uint32 = 0
	errIO    uint32 = 5
	errInval uint32 = 22
	errNoSpc uint32 = 28
)

// Sizes.
const (
	// maxPayload bounds a single READ or WRITE.
	maxPayload = 32 << 20
	// maxOptionLength bounds an option's data; NBD strings are at most 4 KiB.
	maxOptionLength = 4096 + 64
	// sectorSize is the unit a volume size must be a multiple of.
	sectorSize = 512
	// preferredBlockSize is advertised in NBD_INFO_BLOCK_SIZE.
	preferredBlockSize = 4096
	// zeroPadLength is the padding after NBD_OPT_EXPORT_NAME's reply
	// unless both sides set NO_ZEROES.
	zeroPadLength = 124
	// requestHeaderLength is the fixed size of a transmission request.
	requestHeaderLength = 28
)
