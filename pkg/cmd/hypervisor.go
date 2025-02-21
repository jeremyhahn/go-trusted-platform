//go:build libvirt

package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/hypervisor"
	"github.com/spf13/cobra"
)

var (
	cwd         string
	isoPath     string
	diskPath    string
	diskSize    string
	networkName string
	bridgeName  string
	ifaceName   string
	vmName      string
)

func init() {
	var err error

	cwd, err = os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	// hypervisor flags
	hypervisorCmd.Flags().StringVar(&isoPath, "iso", cwd+"/build/docker/trusted-platform-iso-builder/trusted-platform.iso", "Path to the ISO file")
	hypervisorCmd.Flags().StringVar(&diskPath, "disk", cwd+"/build/docker/trusted-platform-iso-builder/trusted-platform.qcow2", "Path to the disk image")
	hypervisorCmd.Flags().StringVar(&diskSize, "disk-size", "10G", "Size of the disk image to create (if it does not exist)")
	hypervisorCmd.Flags().StringVar(&networkName, "network", "trusted-net", "Name of the hypervisor network")
	hypervisorCmd.Flags().StringVar(&bridgeName, "bridge", "trustbr0", "Name of the network bridge")
	hypervisorCmd.Flags().StringVar(&ifaceName, "iface", "eno1", "Physical network interface")
	hypervisorCmd.Flags().StringVar(&vmName, "name", "trusted-platform", "Name of the virtual machine")
	// isoPath = cwd + "/build/docker/trusted-platform-iso-builder/trusted-platform.iso"
	// diskPath = cwd + "/build/docker/trusted-platform-iso-builder/trusted-platform.qcow2"
	// diskSize = "10G"
	// networkName = "trusted-net"
	// bridgeName = "trustbr0"
	// ifaceName = "eno1"
	// vmName = "trusted-platform"

	// createMachine flags
	createMachineCmd.Flags().StringVar(&isoPath, "iso", isoPath, "Path to the ISO file")
	createMachineCmd.Flags().StringVar(&diskPath, "disk", diskPath, "Path to the disk image")
	createMachineCmd.Flags().StringVar(&diskSize, "disk-size", diskSize, "Size of the disk image to create (if it does not exist)")
	createMachineCmd.Flags().StringVar(&networkName, "network", networkName, "Name of the hypervisor network")
	createMachineCmd.Flags().StringVar(&bridgeName, "bridge", bridgeName, "Name of the network bridge")
	createMachineCmd.Flags().StringVar(&ifaceName, "iface", ifaceName, "Physical network interface")
	createMachineCmd.Flags().StringVar(&vmName, "name", vmName, "Name of the virtual machine")

	// deleteNetwork flags
	deleteNetworkCmd.Flags().StringVar(&networkName, "network", networkName, "Name of the hypervisor network")
	deleteNetworkCmd.Flags().StringVar(&bridgeName, "bridge", bridgeName, "Name of the network bridge")

	// deleteMachine flags
	deleteMachineCmd.Flags().StringVar(&vmName, "name", vmName, "Name of the virtual machine")
	deleteMachineCmd.Flags().StringVar(&diskPath, "disk", diskPath, "Path to the disk image")

	// preseed flags
	preseedCmd.Flags().String("locale", "en_US.UTF-8", "The locale for the installation")
	preseedCmd.Flags().String("keyboard-layout", "us", "The keyboard layout")
	preseedCmd.Flags().String("network-interface", "auto", "The network interface to use")
	preseedCmd.Flags().String("hostname", "debian", "The hostname for the system")
	preseedCmd.Flags().String("domain", "trusted-platform.local", "The domain name")
	preseedCmd.Flags().String("apt-mirror-host", "deb.debian.org", "The mirror host for APT")
	preseedCmd.Flags().String("apt-mirror-directory", "/debian", "The directory for APT mirror")
	preseedCmd.Flags().String("root-password", "password", "The root password")
	preseedCmd.Flags().String("user-fullname", "Platform Administrator", "The full name of the user")
	preseedCmd.Flags().String("username", "tpadm", "The username for the user")
	preseedCmd.Flags().String("user-password", "password", "The password for the user")
	preseedCmd.Flags().String("disk", "/dev/vda", "The disk to partition")
	preseedCmd.Flags().Bool("enable-luks", false, "Enable LVM with LUKS partitioning")
	preseedCmd.Flags().StringSlice("packages", []string{"sudo", "vim", "curl", "ssh", "wget", "cron", "docker.io", "python3-ansible-runner", "tpm2-tools", "iputils-ping", "net-tools", "mokutil", "efitools", "efivar"}, "A list of packages to install")
	preseedCmd.Flags().Bool("enable-secure-boot", true, "Enable secure boot")
	preseedCmd.Flags().Bool("enable-efi", true, "Enable EFI")
	preseedCmd.Flags().String("root-volume-fs", "ext4", "File system type for the root (/) volume")
	preseedCmd.Flags().String("root-volume-size", "max", "Size for the root (/) volume (default is the remainder of the disk)")
	preseedCmd.Flags().String("var-volume-fs", "ext4", "File system type for the /var volume")
	preseedCmd.Flags().String("var-volume-size", "20%", "Size for the /var volume (default is 20% of the disk)")

	// Add commands to root
	hypervisorCmd.AddCommand(createMachineCmd)
	hypervisorCmd.AddCommand(deleteNetworkCmd)
	hypervisorCmd.AddCommand(deleteMachineCmd)
	hypervisorCmd.AddCommand(preseedCmd)
	rootCmd.AddCommand(hypervisorCmd)
}

var hypervisorCmd = &cobra.Command{
	Use:   "hypervisor",
	Short: "Hypervisor Management",
}

var createMachineCmd = &cobra.Command{
	Use:   "create-vm",
	Short: "Create a new virtual machine",
	Run: func(cmd *cobra.Command, args []string) {
		config := hypervisor.Config{
			Network: hypervisor.NetworkConfig{
				Name:              networkName,
				Bridge:            bridgeName,
				PhysicalInterface: ifaceName,
			},
			VM: hypervisor.DomainConfig{
				Name:           vmName,
				Memory:         2048,
				VCpu:           2,
				CDROMPath:      isoPath,
				DiskPath:       diskPath,
				DiskSize:       diskSize,
				Network:        networkName,
				GraphicsType:   "spice",
				GraphicsListen: "127.0.0.1",
				TPMPath:        "/dev/tpm0",
				SignalSocket:   fmt.Sprintf("/var/run/libvirt/qemu/%s-channel.sock", vmName),
				ChannelName:    "trusted-platform.0",
			},
		}

		// Connect to libvirt
		conn, err := hypervisor.ConnectToLibvirt()
		if err != nil {
			log.Fatalf("Failed to connect to libvirt: %v", err)
		}
		defer conn.Close()

		// Ensure network exists
		if err := hypervisor.EnsureNetworkExists(conn, config.Network); err != nil {
			log.Fatalf("Failed to ensure network exists: %v", err)
		}

		// Ensure disk exists
		if err := hypervisor.EnsureDiskExists(config.VM.DiskPath, config.VM.DiskSize); err != nil {
			log.Fatalf("Failed to ensure disk exists: %v", err)
		}

		// Ensure the domain exists and start it
		if err := hypervisor.EnsureDomainExists(conn, config.VM, config.Network); err != nil {
			log.Fatalf("Failed to ensure domain exists: %v", err)
		}

		// Start the eject listener
		if err := hypervisor.StartEjectListener(conn, config.VM, config.VM.SignalSocket); err != nil {
			log.Fatalf("Failed to start eject listener: %v", err)
		}

		// Handle OS signals for graceful shutdown
		go func() {
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			sig := <-sigs
			log.Printf("Received signal: %v. Cleaning up...\n", sig)

			// Lookup the domain again to ensure it's still available
			domain, err := conn.LookupDomainByName(config.VM.Name)
			if err == nil {
				// Remove the channel device
				if err := hypervisor.RemoveChannelDevice(conn, domain, config.VM.ChannelName); err != nil {
					log.Printf("Failed to detach channel device '%s': %v\n", config.VM.ChannelName, err)
				}

				// Attempt to remove the socket file
				if err := os.Remove(config.VM.SignalSocket); err != nil && !os.IsNotExist(err) {
					log.Printf("Failed to remove socket file '%s': %v\n", config.VM.SignalSocket, err)
				} else {
					log.Printf("Socket file '%s' removed successfully.\n", config.VM.SignalSocket)
				}
			} else {
				log.Printf("Domain '%s' not found. Skipping channel device removal.\n", config.VM.Name)
			}

			os.Exit(0)
		}()

		fmt.Println("Waiting for installation to complete to eject CD-ROM. Press Ctrl+C to exit.")
		select {}
	},
}

var deleteNetworkCmd = &cobra.Command{
	Use:   "delete-network",
	Short: "Delete the hypervisor network",
	Run: func(cmd *cobra.Command, args []string) {
		config := hypervisor.NetworkConfig{
			Name:   networkName,
			Bridge: bridgeName,
		}
		conn, err := hypervisor.ConnectToLibvirt()
		if err != nil {
			log.Fatalf("Failed to connect to libvirt: %v", err)
		}
		defer conn.Close()

		if err := hypervisor.RemoveNetwork(conn, config); err != nil {
			log.Fatalf("Failed to delete network: %v", err)
		}
	},
}

var deleteMachineCmd = &cobra.Command{
	Use:   "delete-vm",
	Short: "Delete a virtual machine",
	Run: func(cmd *cobra.Command, args []string) {
		config := hypervisor.DomainConfig{
			Name:     vmName,
			DiskPath: diskPath,
		}

		conn, err := hypervisor.ConnectToLibvirt()
		if err != nil {
			log.Fatalf("Failed to connect to libvirt: %v", err)
		}
		defer conn.Close()

		if err := hypervisor.RemoveDomain(conn, config); err != nil {
			log.Fatalf("Failed to delete VM: %v", err)
		}
	},
}

var preseedCmd = &cobra.Command{
	Use:   "preseed [output]",
	Short: "Generates a preseed configuration",
	Run: func(cmd *cobra.Command, args []string) {

		// Parse the preseed flags
		locale, _ := cmd.Flags().GetString("locale")
		keyboardLayout, _ := cmd.Flags().GetString("keyboard-layout")
		networkInterface, _ := cmd.Flags().GetString("network-interface")
		hostname, _ := cmd.Flags().GetString("hostname")
		domain, _ := cmd.Flags().GetString("domain")
		aptMirrorHost, _ := cmd.Flags().GetString("apt-mirror-host")
		aptMirrorDirectory, _ := cmd.Flags().GetString("apt-mirror-directory")
		rootPassword, _ := cmd.Flags().GetString("root-password")
		userFullname, _ := cmd.Flags().GetString("user-fullname")
		username, _ := cmd.Flags().GetString("username")
		userPassword, _ := cmd.Flags().GetString("user-password")
		disk, _ := cmd.Flags().GetString("disk")
		enableLUKS, _ := cmd.Flags().GetBool("enable-luks")
		packages, _ := cmd.Flags().GetStringSlice("packages")
		enableSecureBoot, _ := cmd.Flags().GetBool("enable-secure-boot")
		enableEFI, _ := cmd.Flags().GetBool("enable-efi")
		rootVolumeFS, _ := cmd.Flags().GetString("root-volume-fs")
		rootVolumeSize, _ := cmd.Flags().GetString("root-volume-size")
		varVolumeFS, _ := cmd.Flags().GetString("var-volume-fs")
		varVolumeSize, _ := cmd.Flags().GetString("var-volume-size")

		// Create and populate the preseed configuration struct
		config := hypervisor.PreseedConfig{
			Locale:             locale,
			KeyboardLayout:     keyboardLayout,
			NetworkInterface:   networkInterface,
			Hostname:           hostname,
			Domain:             domain,
			AptMirrorHost:      aptMirrorHost,
			AptMirrorDirectory: aptMirrorDirectory,
			RootPassword:       rootPassword,
			UserFullname:       userFullname,
			Username:           username,
			UserPassword:       userPassword,
			Disk:               disk,
			EnableLUKS:         enableLUKS,
			Packages:           packages,
			EnableSecureBoot:   enableSecureBoot,
			EnableEFI:          enableEFI,
			RootVolumeFS:       rootVolumeFS,
			RootVolumeSize:     rootVolumeSize,
			VarVolumeFS:        varVolumeFS,
			VarVolumeSize:      varVolumeSize,
		}

		// Generate preseed config content
		preseed, err := hypervisor.NewPreseedConfig(config)
		if err != nil {
			log.Fatalf("Failed to generate preseed configuration: %v", err)
		}
		output := "preseed.cfg"
		if len(args) > 0 {
			output = args[0]
		}
		if err := os.WriteFile(output, preseed, 0644); err != nil {
			log.Fatalf("Failed to write preseed configuration to file: %v", err)
		}
	},
}
