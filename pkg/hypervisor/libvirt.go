// go:build libvirt

package hypervisor

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/libvirt/libvirt-go"
	libvirtxml "github.com/libvirt/libvirt-go-xml"
)

type Config struct {
	Network NetworkConfig
	VM      DomainConfig
}

type NetworkConfig struct {
	Name              string
	Bridge            string
	PhysicalInterface string
}

type DomainConfig struct {
	Name           string
	Memory         uint
	VCpu           uint
	ChannelName    string
	CDROMPath      string
	DiskPath       string
	DiskSize       string
	Network        string
	GraphicsKeymap string
	GraphicsPort   int
	GraphicsType   string
	GraphicsListen string
	SpicePassword  string
	SignalSocket   string
	TPMPath        string
}

func EnsureRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this operation requires root privileges. Please run as root or with sudo")
	}
	return nil
}

// EjectCDROM sets the CD-ROM media to 'none' to eject it without detaching the device.
// EjectCDROM sets the CD-ROM media to 'empty' to eject it without detaching the device.
func EjectCDROM(conn *libvirt.Connect, domain *libvirt.Domain, targetDev string) error {
	// Define the new media source as 'empty' to eject the CD-ROM.
	deviceXML := fmt.Sprintf(`
<disk type='file' device='cdrom'>
  <driver name='qemu' type='raw'/>
  <source media='empty'/>
  <target dev='%s' bus='ide'/>
  <readonly/>
</disk>`, targetDev)

	// Define flags
	flags := (libvirt.DOMAIN_DEVICE_MODIFY_LIVE |
		libvirt.DOMAIN_DEVICE_MODIFY_CONFIG |
		libvirt.DOMAIN_DEVICE_MODIFY_FORCE)

	// Change media to 'empty' to eject
	err := domain.UpdateDeviceFlags(deviceXML, flags)
	if err != nil {
		return fmt.Errorf("failed to eject CD-ROM: %v", err)
	}

	// Get domain name for logging
	name, err := domain.GetName()
	if err != nil {
		log.Printf("CD-ROM ejected successfully from domain (unknown name).\n")
	} else {
		log.Printf("CD-ROM ejected successfully from domain '%s'.\n", name)
	}

	return nil
}

func StartEjectListener(conn *libvirt.Connect, vmConfig DomainConfig, socketPath string) error {
	domain, err := conn.LookupDomainByName(vmConfig.Name)
	if err != nil {
		return fmt.Errorf("failed to lookup domain '%s': %v", vmConfig.Name, err)
	}

	go func() {
		if err := ListenForSignals(socketPath, func(message string) {
			if strings.TrimSpace(message) == "eject" {
				domainName, err := domain.GetName()
				if err != nil {
					log.Printf("Failed to get domain name: %v\n", err)
					return
				}

				log.Printf("Received 'eject' signal. Waiting 10 seconds before ejecting CD-ROM for domain '%s'...\n", domainName)
				time.Sleep(15 * time.Second)
				log.Printf("Ejecting CD-ROM for domain '%s' now.\n", domainName)
				if err := EjectCDROM(conn, domain, "hda"); err != nil { // Replace "hda" with your CD-ROM target device if different
					log.Printf("Failed to eject CD-ROM for domain '%s': %v\n", domainName, err)
				} else {
					log.Printf("CD-ROM for domain '%s' ejected successfully.\n", domainName)

					// Remove the UNIX socket file
					if err := os.Remove(socketPath); err != nil {
						log.Printf("Failed to remove socket file '%s': %v\n", socketPath, err)
					} else {
						log.Printf("Socket file '%s' removed successfully.\n", socketPath)
					}

					// Remove the channel device
					if err := RemoveChannelDevice(conn, domain, vmConfig.ChannelName); err != nil {
						log.Printf("Failed to detach channel device '%s': %v\n", vmConfig.ChannelName, err)
					}

					os.Exit(0)
				}
			} else {
				log.Printf("Received unknown signal: '%s'\n", message)
			}
		}); err != nil {
			log.Fatalf("Error listening for signals: %v", err)
		}
	}()

	return nil
}

func ListenForSignals(socketPath string, callback func(string)) error {
	// Remove the socket file if it already exists to avoid binding errors.
	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket '%s': %v", socketPath, err)
	}
	defer listener.Close()

	// Set appropriate permissions for the socket
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("failed to set permissions on socket '%s': %v", socketPath, err)
	}

	log.Printf("Listening for CD-ROM eject signal on UNIX socket '%s'...\n", socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		log.Printf("Accepted connection from '%s'\n", conn.RemoteAddr())

		go handleConnection(conn, callback)
	}
}

// handleConnection processes messages from a single UNIX socket connection.
func handleConnection(conn net.Conn, callback func(string)) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := scanner.Text()
		log.Printf("Received message: %s\n", message)
		callback(message)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading from connection: %v\n", err)
	} else {
		log.Println("Connection closed by remote.")
	}
}

// InitializeLibvirtEvents initializes the libvirt event loop
func InitializeLibvirtEvents() error {
	if err := libvirt.EventRegisterDefaultImpl(); err != nil {
		return fmt.Errorf("failed to register libvirt event loop: %v", err)
	}
	return nil
}

// -------------------- Utility Functions --------------------

func ConnectToLibvirt() (*libvirt.Connect, error) {
	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}
	return conn, nil
}

// -------------------- Disk Management --------------------

func EnsureDiskExists(diskPath, diskSize string) error {
	if _, err := os.Stat(diskPath); os.IsNotExist(err) {
		fmt.Printf("Disk image '%s' does not exist. Creating...\n", diskPath)
		cmd := exec.Command("qemu-img", "create", "-f", "qcow2", diskPath, diskSize)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to create disk image '%s': %v, output: %s", diskPath, err, string(output))
		}
		fmt.Printf("Disk image '%s' created successfully.\n", diskPath)
	} else if err != nil {
		return fmt.Errorf("error checking disk image '%s': %v", diskPath, err)
	} else {
		fmt.Printf("Disk image '%s' already exists.\n", diskPath)
	}
	return nil
}

// -------------------- Network Management --------------------

func EnsureNetworkExists(conn *libvirt.Connect, config NetworkConfig) error {

	network, err := conn.LookupNetworkByName(config.Name)
	if err == nil {
		fmt.Printf("Network '%s' already exists.\n", config.Name)
		defer network.Free()
	} else {

		if err := EnsureRoot(); err != nil {
			return err
		}

		networkDef := &libvirtxml.Network{
			Name: config.Name,
			Bridge: &libvirtxml.NetworkBridge{
				Name: config.Bridge,
			},
		}

		networkXML, err := networkDef.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal network XML: %v", err)
		}

		network, err = conn.NetworkDefineXML(networkXML)
		if err != nil {
			return fmt.Errorf("failed to define network: %v", err)
		}
		defer network.Free()

		if err := network.Create(); err != nil {
			return fmt.Errorf("failed to create network: %v", err)
		}
	}

	if err := configureBridgeNetworking(config); err != nil {
		return fmt.Errorf("failed to configure bridge networking: %v", err)
	}

	fmt.Printf("Network '%s' configured successfully.\n", config.Name)
	return nil
}

func configureBridgeNetworking(config NetworkConfig) error {
	// Check if the bridge already exists
	if err := exec.Command("ip", "link", "show", config.Bridge).Run(); err == nil {
		fmt.Printf("Bridge '%s' already exists. Skipping creation.\n", config.Bridge)
	} else {
		// Create the bridge
		if err := exec.Command("ip", "link", "add", "name", config.Bridge, "type", "bridge").Run(); err != nil {
			return fmt.Errorf("failed to create bridge '%s': %v", config.Bridge, err)
		}
	}

	// Get the current IP configuration of the physical interface
	ipConfig, err := getInterfaceIPConfig(config.PhysicalInterface)
	if err != nil {
		return fmt.Errorf("failed to get IP configuration for '%s': %v", config.PhysicalInterface, err)
	}

	// Check if the bridge already has the correct IP assigned
	bridgeIPConfig, _ := getInterfaceIPConfig(config.Bridge) // Ignore error if the bridge doesn't have an IP
	if bridgeIPConfig["ip"] == ipConfig["ip"] && bridgeIPConfig["mask"] == ipConfig["mask"] {
		fmt.Printf("Bridge '%s' already has the correct IP assigned. Skipping IP configuration.\n", config.Bridge)
	} else {
		// Flush IP configuration from the physical interface
		if err := exec.Command("ip", "addr", "flush", "dev", config.PhysicalInterface).Run(); err != nil {
			return fmt.Errorf("failed to flush IP configuration on '%s': %v", config.PhysicalInterface, err)
		}

		// Add the physical interface to the bridge
		if err := exec.Command("ip", "link", "set", config.PhysicalInterface, "master", config.Bridge).Run(); err != nil {
			return fmt.Errorf("failed to add interface '%s' to bridge '%s': %v", config.PhysicalInterface, config.Bridge, err)
		}

		// Assign the IP configuration to the bridge
		if err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ipConfig["ip"], ipConfig["mask"]), "dev", config.Bridge).Run(); err != nil {
			return fmt.Errorf("failed to assign IP to bridge '%s': %v", config.Bridge, err)
		}
	}

	// Ensure the physical interface is up
	if err := exec.Command("ip", "link", "set", config.PhysicalInterface, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up interface '%s': %v", config.PhysicalInterface, err)
	}

	// Bring up the bridge
	if err := exec.Command("ip", "link", "set", config.Bridge, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up bridge '%s': %v", config.Bridge, err)
	}

	// Check if the default route already exists for the bridge
	existingDefaultRoute, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		fmt.Printf("Failed to check existing default route. Proceeding with route setup... Error: %v\n", err)
	}
	if strings.Contains(string(existingDefaultRoute), config.Bridge) {
		fmt.Printf("Default route already set via bridge '%s'. Skipping route configuration.\n", config.Bridge)
	} else {
		// Delete any existing default route
		if len(existingDefaultRoute) > 0 {
			if err := exec.Command("ip", "route", "del", "default").Run(); err != nil {
				fmt.Printf("Failed to delete existing default route. Proceeding with adding new route... Error: %v\n", err)
			} else {
				fmt.Println("Existing default route deleted.")
			}
		}

		// Add the default route via the bridge
		addRouteCmd := exec.Command("ip", "route", "add", "default", "via", ipConfig["gateway"], "dev", config.Bridge)
		addRouteOutput, err := addRouteCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set default route via bridge '%s': %v, output: %s", config.Bridge, err, string(addRouteOutput))
		}
		fmt.Printf("Default route added via bridge '%s'.\n", config.Bridge)
	}

	fmt.Printf("Bridge '%s' configured successfully with IP and routing.\n", config.Bridge)
	return nil
}

func restorePhysicalInterface(config NetworkConfig) error {
	// Get the IP configuration from the bridge
	ipConfig, err := getInterfaceIPConfig(config.Bridge)
	if err != nil {
		return fmt.Errorf("failed to get IP configuration for bridge '%s': %v", config.Bridge, err)
	}

	// Bring down the bridge
	if err := exec.Command("ip", "link", "set", config.Bridge, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down bridge '%s': %v", config.Bridge, err)
	}

	// Remove the bridge
	if err := exec.Command("ip", "link", "delete", config.Bridge).Run(); err != nil {
		return fmt.Errorf("failed to delete bridge '%s': %v", config.Bridge, err)
	}

	// Assign the IP configuration back to the physical interface
	if err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", ipConfig["ip"], ipConfig["mask"]), "dev", config.PhysicalInterface).Run(); err != nil {
		return fmt.Errorf("failed to restore IP to interface '%s': %v", config.PhysicalInterface, err)
	}

	// Bring up the physical interface
	if err := exec.Command("ip", "link", "set", config.PhysicalInterface, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring up interface '%s': %v", config.PhysicalInterface, err)
	}

	// Restore the default route to use the physical interface
	if err := exec.Command("ip", "route", "add", "default", "via", ipConfig["gateway"], "dev", config.PhysicalInterface).Run(); err != nil {
		return fmt.Errorf("failed to set default route via interface '%s': %v", config.PhysicalInterface, err)
	}

	fmt.Printf("Physical interface '%s' restored successfully.\n", config.PhysicalInterface)
	return nil
}

func getInterfaceIPConfig(interfaceName string) (map[string]string, error) {
	cmd := exec.Command("ip", "-4", "addr", "show", interfaceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get IP configuration for '%s': %v, output: %s", interfaceName, err, string(output))
	}

	ipConfig := make(map[string]string)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.Contains(line, "inet") {
			fields := strings.Fields(line)
			ipWithMask := strings.Split(fields[1], "/")
			ipConfig["ip"] = ipWithMask[0]
			ipConfig["mask"] = ipWithMask[1]
		}
	}

	cmd = exec.Command("ip", "route", "show", "default", "dev", interfaceName)
	routeOutput, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway for '%s': %v, output: %s", interfaceName, err, string(routeOutput))
	}

	routeLines := strings.Split(string(routeOutput), "\n")
	for _, routeLine := range routeLines {
		if strings.HasPrefix(routeLine, "default via") {
			fields := strings.Fields(routeLine)
			ipConfig["gateway"] = fields[2]
		}
	}

	if len(ipConfig) == 0 {
		return nil, fmt.Errorf("no IP configuration found for '%s'", interfaceName)
	}

	return ipConfig, nil
}

func deleteBridge(bridgeName string) error {
	if err := exec.Command("ip", "link", "show", bridgeName).Run(); err != nil {
		fmt.Printf("Bridge '%s' does not exist. Skipping deletion.\n", bridgeName)
		return nil
	}

	if err := exec.Command("ip", "link", "set", bridgeName, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down bridge '%s': %v", bridgeName, err)
	}

	if err := exec.Command("ip", "link", "delete", bridgeName).Run(); err != nil {
		return fmt.Errorf("failed to delete bridge '%s': %v", bridgeName, err)
	}

	fmt.Printf("Bridge '%s' deleted successfully.\n", bridgeName)
	return nil
}

func RemoveNetwork(conn *libvirt.Connect, config NetworkConfig) error {
	// Remove the network
	network, err := conn.LookupNetworkByName(config.Name)
	if err == nil {
		defer network.Free()
		if err := network.Destroy(); err != nil && !strings.Contains(err.Error(), "Network is not active") {
			return fmt.Errorf("failed to destroy network '%s': %v", config.Name, err)
		}
		if err := network.Undefine(); err != nil {
			return fmt.Errorf("failed to undefine network '%s': %v", config.Name, err)
		}
		fmt.Printf("Network '%s' removed successfully.\n", config.Name)
	}

	// Delete the bridge
	if err := deleteBridge(config.Bridge); err != nil {
		fmt.Printf("Failed to delete bridge '%s': %v\n", config.Bridge, err)
	}

	// Restore the physical interface
	if err := restorePhysicalInterface(config); err != nil {
		return fmt.Errorf("failed to restore physical interface: %v", err)
	}

	return nil
}

// -------------------- Domain Management --------------------
func EnsureDomainExists(conn *libvirt.Connect, vmConfig DomainConfig, netConfig NetworkConfig) error {
	domain, err := conn.LookupDomainByName(vmConfig.Name)
	if err == nil {
		fmt.Printf("Domain '%s' already exists.\n", vmConfig.Name)
		domain.Free()
		return nil
	}

	if err := InitializeLibvirtEvents(); err != nil {
		log.Fatalf("Failed to initialize libvirt events: %v", err)
	}

	// reconnectTimeout := uint(10)

	domainDef := &libvirtxml.Domain{
		Type: "kvm",
		Name: vmConfig.Name,
		Memory: &libvirtxml.DomainMemory{
			Value: vmConfig.Memory * 1024,
			Unit:  "KiB",
		},
		CurrentMemory: &libvirtxml.DomainCurrentMemory{
			Value: vmConfig.Memory * 1024,
			Unit:  "KiB",
		},
		VCPU: &libvirtxml.DomainVCPU{
			Value:     vmConfig.VCpu,
			Placement: "static",
		},
		CPUTune: &libvirtxml.DomainCPUTune{
			VCPUPin: []libvirtxml.DomainCPUTuneVCPUPin{
				{VCPU: 0, CPUSet: "0"},
				{VCPU: 1, CPUSet: "1"},
			},
		},
		OS: &libvirtxml.DomainOS{
			Type: &libvirtxml.DomainOSType{
				Arch:    "x86_64",
				Machine: "pc-i440fx-8.2",
				Type:    "hvm",
			},
			BootDevices: []libvirtxml.DomainBootDevice{
				{Dev: "cdrom"},
				{Dev: "hd"},
			},
		},
		Features: &libvirtxml.DomainFeatureList{
			ACPI: &libvirtxml.DomainFeature{},
			APIC: &libvirtxml.DomainFeatureAPIC{},
			PAE:  &libvirtxml.DomainFeature{},
		},
		CPU: &libvirtxml.DomainCPU{
			Mode:       "host-passthrough",
			Check:      "none",
			Migratable: "on",
		},
		Clock: &libvirtxml.DomainClock{
			Offset: "utc",
		},
		OnPoweroff: "destroy",
		OnReboot:   "restart",
		OnCrash:    "destroy",
		Devices: &libvirtxml.DomainDeviceList{
			Emulator: "/usr/bin/qemu-system-x86_64",
			Channels: []libvirtxml.DomainChannel{
				{
					Source: &libvirtxml.DomainChardevSource{
						UNIX: &libvirtxml.DomainChardevSourceUNIX{
							Mode: "connect",
							Path: fmt.Sprintf("/var/run/libvirt/qemu/%s-channel.sock", vmConfig.Name),
							// Reconnect: &libvirtxml.DomainChardevSourceReconnect{
							// 	Enabled: "yes",
							// 	Timeout: &reconnectTimeout,
							// },
						},
					},
					// Alias: &libvirtxml.DomainAlias{
					// 	Name: "virtio-serial0",
					// },
					Target: &libvirtxml.DomainChannelTarget{
						VirtIO: &libvirtxml.DomainChannelTargetVirtIO{
							Name: "trusted-platform.0",
						},
					},
				},
			},
			Disks: []libvirtxml.DomainDisk{
				{
					Device: "disk",
					Driver: &libvirtxml.DomainDiskDriver{
						Name:  "qemu",
						Type:  "qcow2",
						Cache: "writeback",
					},
					Source: &libvirtxml.DomainDiskSource{
						File: &libvirtxml.DomainDiskSourceFile{
							File: vmConfig.DiskPath,
						},
					},
					Target: &libvirtxml.DomainDiskTarget{
						Dev: "vda",
						Bus: "virtio",
					},
				},
				{
					Device: "cdrom",
					Driver: &libvirtxml.DomainDiskDriver{
						Name: "qemu",
						Type: "raw",
					},
					Source: &libvirtxml.DomainDiskSource{
						File: &libvirtxml.DomainDiskSourceFile{
							File: vmConfig.CDROMPath,
						},
					},
					Target: &libvirtxml.DomainDiskTarget{
						Dev: "hda",
						Bus: "ide",
					},
					ReadOnly: &libvirtxml.DomainDiskReadOnly{},
				},
			},
			Interfaces: []libvirtxml.DomainInterface{
				{
					Source: &libvirtxml.DomainInterfaceSource{
						Bridge: &libvirtxml.DomainInterfaceSourceBridge{
							Bridge: netConfig.Bridge, // Pass bridge name dynamically
						},
					},
					Model: &libvirtxml.DomainInterfaceModel{
						Type: "virtio",
					},
				},
			},
			Graphics: []libvirtxml.DomainGraphic{
				{
					Spice: &libvirtxml.DomainGraphicSpice{
						Port:     -1,
						AutoPort: "yes",
						Listen:   "127.0.0.1",
						Keymap:   "en-us",
						Passwd:   vmConfig.SpicePassword,
					},
				},
			},
			TPMs: []libvirtxml.DomainTPM{
				{
					Model: "tpm-tis",
					Backend: &libvirtxml.DomainTPMBackend{
						Passthrough: &libvirtxml.DomainTPMBackendPassthrough{
							Device: &libvirtxml.DomainTPMBackendDevice{
								Path: vmConfig.TPMPath,
							},
						},
					},
				},
			},
			Videos: []libvirtxml.DomainVideo{
				{
					Model: libvirtxml.DomainVideoModel{
						Type:    "virtio",
						Heads:   1,
						Primary: "yes",
					},
				},
			},
		},
		SecLabel: []libvirtxml.DomainSecLabel{
			{
				Type:  "none",
				Model: "apparmor",
			},
		},
	}

	domainXML, err := domainDef.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal domain XML: %v", err)
	}

	domain, err = conn.DomainDefineXML(domainXML)
	if err != nil {
		return fmt.Errorf("failed to define domain: %v", err)
	}
	defer domain.Free()

	if err := StartEjectListener(conn, vmConfig, vmConfig.SignalSocket); err != nil {
		return fmt.Errorf("failed to start eject listener: %v", err)
	}

	if err := domain.Create(); err != nil {
		return fmt.Errorf("failed to create domain: %v", err)
	}

	fmt.Printf("Domain '%s' started successfully.\n", vmConfig.Name)
	return nil
}

func RemoveDomain(conn *libvirt.Connect, config DomainConfig) error {
	domain, err := conn.LookupDomainByName(config.Name)
	if err != nil {
		return fmt.Errorf("domain '%s' does not exist: %v", config.Name, err)
	}
	defer domain.Free()

	// Retrieve domain name
	domainName, err := domain.GetName()
	if err != nil {
		return fmt.Errorf("failed to get domain name: %v", err)
	}

	// Remove the channel device first
	if err := RemoveChannelDevice(conn, domain, config.ChannelName); err != nil {
		log.Printf("Warning: Failed to detach channel device '%s': %v\n", config.ChannelName, err)
		// Continue with the removal process even if channel removal fails
	}

	// Destroy the domain if it's running
	err = domain.Destroy()
	if err != nil {
		if libvirtError, ok := err.(libvirt.Error); ok && libvirtError.Code == libvirt.ERR_OPERATION_INVALID {
			fmt.Printf("Domain '%s' is not running. Proceeding with undefine.\n", domainName)
		} else {
			return fmt.Errorf("failed to destroy domain '%s': %v", domainName, err)
		}
	}

	// Undefine the domain
	err = domain.Undefine()
	if err != nil {
		return fmt.Errorf("failed to undefine domain '%s': %v", domainName, err)
	}

	// Remove the disk image if it exists
	if _, err := os.Stat(config.DiskPath); err == nil {
		err = os.Remove(config.DiskPath)
		if err != nil {
			return fmt.Errorf("failed to remove disk image '%s': %v", config.DiskPath, err)
		}
		fmt.Printf("Disk image '%s' removed successfully.\n", config.DiskPath)
	}

	// Remove the UNIX socket file if it exists
	if config.SignalSocket != "" {
		if _, err := os.Stat(config.SignalSocket); err == nil {
			err = os.Remove(config.SignalSocket)
			if err != nil {
				fmt.Printf("Failed to remove socket file '%s': %v\n", config.SignalSocket, err)
			} else {
				fmt.Printf("Socket file '%s' removed successfully.\n", config.SignalSocket)
			}
		} else {
			fmt.Printf("Socket file '%s' does not exist. Skipping removal.\n", config.SignalSocket)
		}
	}

	fmt.Printf("Domain '%s' removed successfully.\n", domainName)
	return nil
}

// RemoveChannelDevice safely removes the specified channel device from the domain.
// It first attempts a live detachment. If that fails due to unsupported flags,
// it will shut down the VM, detach the device, and then restart the VM.
func RemoveChannelDevice(conn *libvirt.Connect, domain *libvirt.Domain, channelName string) error {
	// Retrieve the current devices XML
	domainXML, err := domain.GetXMLDesc(libvirt.DOMAIN_XML_MIGRATABLE | libvirt.DOMAIN_XML_INACTIVE)
	if err != nil {
		return fmt.Errorf("failed to get domain XML: %v", err)
	}

	// Parse the XML to find the channel device
	var domainStruct libvirtxml.Domain
	err = domainStruct.Unmarshal(domainXML)
	if err != nil {
		return fmt.Errorf("failed to parse domain XML: %v", err)
	}

	// Find the channel device with the specified name
	var channelDevice *libvirtxml.DomainChannel
	for _, channel := range domainStruct.Devices.Channels {
		if channel.Target != nil && channel.Target.VirtIO != nil && channel.Target.VirtIO.Name == channelName {
			channelDevice = &channel
			break
		}
	}

	if channelDevice == nil {
		return fmt.Errorf("channel device '%s' not found in domain", channelName)
	}

	// Create a copy of the channel device without the address for detachment
	channelDeviceCopy := *channelDevice
	channelDeviceCopy.Address = nil
	deviceXML, err := channelDeviceCopy.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal channel device XML: %v", err)
	}

	log.Printf("Attempting to detach channel device '%s' with XML:\n%s\n", channelName, deviceXML)

	// Attempt live detachment first without FORCE flag
	flags := libvirt.DOMAIN_DEVICE_MODIFY_LIVE | libvirt.DOMAIN_DEVICE_MODIFY_CONFIG
	err = domain.DetachDeviceFlags(deviceXML, flags)
	if err == nil {
		log.Printf("Channel device '%s' detached successfully (live).\n", channelName)
		return nil
	}

	// Check if the error is due to unsupported flags
	if libvirtErr, ok := err.(libvirt.Error); ok && libvirtErr.Code == libvirt.ERR_OPERATION_UNSUPPORTED {
		log.Printf("Live detachment of channel device '%s' is unsupported. Attempting to shut down the VM and detach.\n", channelName)

		// Retrieve domain name
		domainName, err := domain.GetName()
		if err != nil {
			return fmt.Errorf("failed to get domain name: %v", err)
		}

		// Shut down the VM gracefully
		if err := domain.Shutdown(); err != nil {
			return fmt.Errorf("failed to shut down domain '%s' for device detachment: %v", domainName, err)
		}
		log.Printf("Domain '%s' shut down successfully.\n", domainName)

		// Wait for the domain to shut down
		for {
			state, _, err := domain.GetState()
			if err != nil {
				return fmt.Errorf("failed to get state of domain '%s': %v", domainName, err)
			}
			if state != libvirt.DOMAIN_RUNNING {
				break
			}
			time.Sleep(1 * time.Second)
		}
		log.Printf("Domain '%s' is no longer running.\n", domainName)

		// Detach the channel device without LIVE flag
		flags = libvirt.DOMAIN_DEVICE_MODIFY_CONFIG
		log.Printf("Attempting to detach channel device '%s' without LIVE flag.\n", channelName)
		err = domain.DetachDeviceFlags(deviceXML, flags)
		if err != nil {
			return fmt.Errorf("failed to detach channel device '%s' after shutting down: %v", channelName, err)
		}
		log.Printf("Channel device '%s' detached successfully (after shutdown).\n", channelName)

		// Restart the VM
		if err := domain.Create(); err != nil {
			return fmt.Errorf("failed to restart domain '%s' after detaching channel device: %v", domainName, err)
		}
		log.Printf("Domain '%s' restarted successfully.\n", domainName)

		return nil
	}

	// If the error is not related to unsupported flags, return it
	return fmt.Errorf("failed to detach channel device '%s': %v", channelName, err)
}
