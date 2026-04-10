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

package netlink_test

import (
	"fmt"
	"log"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netlink"
)

// ExampleManager_CreateTAP demonstrates creating a TAP device
func ExampleManager_CreateTAP() {
	// Create a manager
	m := netlink.NewManager()

	// Configure TAP device
	config := &netlink.TAPConfig{
		Name:       "tap0",
		Owner:      1000,
		Group:      1000,
		MultiQueue: false,
		Persist:    false,
		MTU:        1500,
	}

	// Create the TAP device (requires CAP_NET_ADMIN)
	if err := m.CreateTAP(config); err != nil {
		log.Printf("Failed to create TAP device: %v", err)
		return
	}

	// Cleanup
	defer func() {
		if err := m.DeleteTAP("tap0"); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	fmt.Println("TAP device created successfully")
}

// ExampleManager_CreateTAPSimple demonstrates creating a TAP device with simple API
func ExampleManager_CreateTAPSimple() {
	m := netlink.NewManager()

	// Create TAP device with simple parameters
	if err := m.CreateTAPSimple("tap0", 1000, 1000); err != nil {
		log.Printf("Failed to create TAP device: %v", err)
		return
	}

	defer func() {
		if err := m.DeleteTAP("tap0"); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	fmt.Println("TAP device created")
}

// ExampleManager_GetLink demonstrates retrieving link information
func ExampleManager_GetLink() {
	m := netlink.NewManager()

	// Get loopback interface information
	info, err := m.GetLink("lo")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Interface: %s\n", info.Name)
	fmt.Printf("MTU: %d\n", info.MTU)
	fmt.Printf("Type: %s\n", info.Type)
}

// ExampleManager_ListLinks demonstrates listing all network links
func ExampleManager_ListLinks() {
	m := netlink.NewManager()

	links, err := m.ListLinks()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d interfaces\n", len(links))
	for _, link := range links {
		fmt.Printf("  - %s (%s)\n", link.Name, link.Type)
	}
}

// ExampleManager_SetLinkUp demonstrates bringing an interface up
func ExampleManager_SetLinkUp() {
	m := netlink.NewManager()

	// This example shows the API usage
	// Actual execution requires CAP_NET_ADMIN
	if os.Geteuid() != 0 {
		fmt.Println("Requires root privileges")
		return
	}

	// Create a TAP device first
	config := &netlink.TAPConfig{
		Name:  "tap-test",
		Owner: uint32(os.Getuid()),
		Group: uint32(os.Getgid()),
	}

	if err := m.CreateTAP(config); err != nil {
		log.Printf("Failed to create TAP: %v", err)
		return
	}
	defer func() {
		if err := m.DeleteTAP("tap-test"); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	// Bring it up
	if err := m.SetLinkUp("tap-test"); err != nil {
		log.Printf("Failed to bring interface up: %v", err)
		return
	}

	fmt.Println("Interface is up")
}

// ExampleManager_ListTAPs demonstrates listing TAP devices
func ExampleManager_ListTAPs() {
	m := netlink.NewManager()

	taps, err := m.ListTAPs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d TAP devices\n", len(taps))
	for _, tap := range taps {
		fmt.Printf("  - %s (Owner: %d, Group: %d)\n",
			tap.Name, tap.Owner, tap.Group)
	}
}

// Example_errorHandling demonstrates handling typed errors
func Example_errorHandling() {
	m := netlink.NewManager()

	// Try to get a non-existent interface
	_, err := m.GetLink("nonexistent")
	if err != nil {
		var netlinkErr *netlink.NetlinkError
		if ne, ok := err.(*netlink.NetlinkError); ok {
			netlinkErr = ne
		}

		if netlinkErr != nil {
			switch netlinkErr.Type {
			case netlink.ErrorTypeNotFound:
				fmt.Println("Interface not found")
			case netlink.ErrorTypePermission:
				fmt.Println("Permission denied")
			default:
				fmt.Printf("Error: %v\n", err)
			}
		}
	}

	// Output: Interface not found
}

// Example_checkFlags demonstrates checking interface flags
func Example_checkFlags() {
	m := netlink.NewManager()

	info, err := m.GetLink("lo")
	if err != nil {
		log.Fatal(err)
	}

	if netlink.IsUp(info.Flags) {
		fmt.Println("Interface is administratively up")
	}

	if netlink.IsRunning(info.Flags) {
		fmt.Println("Interface is running (link detected)")
	}

	// Output:
	// Interface is administratively up
	// Interface is running (link detected)
}
