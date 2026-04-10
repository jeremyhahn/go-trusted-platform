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

/*
Package netlink provides thread-safe TAP device management using Linux netlink.

This package wraps github.com/vishvananda/netlink to provide a clean, idiomatic
Go interface for managing TAP devices and network links without shelling out
to external commands.

Features:
  - TAP device creation with user/group ownership
  - TAP device deletion
  - Link state management (up/down)
  - MTU configuration
  - Thread-safe operations
  - Typed errors (no fmt.Errorf)
  - Comprehensive error handling

Thread Safety:

All operations are protected by a read-write mutex to ensure thread-safe
concurrent access. Read operations (Get, List) acquire a read lock, while
write operations (Create, Delete, SetUp, SetDown) acquire a write lock.

Error Handling:

All errors are typed using the NetlinkError type, which provides structured
error information including error type, message, and underlying cause. Errors
can be unwrapped using errors.As() and errors.Is().

Basic Usage:

	// Create a manager
	m := netlink.NewManager()

	// Create a TAP device (requires CAP_NET_ADMIN)
	config := &netlink.TAPConfig{
		Name:  "tap0",
		Owner: 1000,
		Group: 1000,
		MTU:   1500,
	}
	if err := m.CreateTAP(config); err != nil {
		log.Fatal(err)
	}

	// Bring the interface up
	if err := m.SetTAPUp("tap0"); err != nil {
		log.Fatal(err)
	}

	// Get interface information
	info, err := m.GetTAP("tap0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Interface: %s, MTU: %d\n", info.Name, info.MTU)

	// List all TAP devices
	taps, err := m.ListTAPs()
	if err != nil {
		log.Fatal(err)
	}
	for _, tap := range taps {
		fmt.Printf("TAP: %s\n", tap.Name)
	}

	// Bring the interface down
	if err := m.SetTAPDown("tap0"); err != nil {
		log.Fatal(err)
	}

	// Delete the interface
	if err := m.DeleteTAP("tap0"); err != nil {
		log.Fatal(err)
	}

Simple API:

	m := netlink.NewManager()

	// Create with simple parameters
	err := m.CreateTAPSimple("tap0", 1000, 1000)

Permissions:

Most operations require CAP_NET_ADMIN capability (typically root). Operations
that fail due to insufficient permissions will return errors of type
ErrorTypePermission.

Error Types:

  - ErrorTypeInvalidName: Invalid interface name
  - ErrorTypeNotFound: Interface not found
  - ErrorTypeAlreadyExists: Interface already exists
  - ErrorTypeCreateFailed: Failed to create interface
  - ErrorTypeDeleteFailed: Failed to delete interface
  - ErrorTypeSetupFailed: Failed to configure interface
  - ErrorTypeStateFailed: Failed to change interface state
  - ErrorTypePermission: Insufficient permissions

Checking Error Types:

	err := m.CreateTAP(config)
	if err != nil {
		var netlinkErr *netlink.NetlinkError
		if errors.As(err, &netlinkErr) {
			switch netlinkErr.Type {
			case netlink.ErrorTypePermission:
				// Handle permission error
			case netlink.ErrorTypeAlreadyExists:
				// Handle duplicate
			default:
				// Handle other errors
			}
		}
	}

Performance Considerations:

The package uses a single manager-level mutex to protect all operations.
For high-performance scenarios with many concurrent operations, consider
creating multiple Manager instances, each managing a subset of interfaces.

Link State Flags:

The package provides helper functions to check interface flags:

	info, _ := m.GetLink("tap0")
	if netlink.IsUp(info.Flags) {
		fmt.Println("Interface is up")
	}
	if netlink.IsRunning(info.Flags) {
		fmt.Println("Interface is running (link detected)")
	}
*/
package netlink
