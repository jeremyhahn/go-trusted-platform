//go:build libvirt

package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/hypervisor"
	"github.com/spf13/cobra"
)

func init() {
	ovmfCmd.AddCommand(ovmfParseCmd)
	rootCmd.AddCommand(ovmfCmd)

	// Add --json flag for JSON output
	ovmfParseCmd.Flags().BoolP("json", "j", false, "Output variables in JSON format")
}

var ovmfCmd = &cobra.Command{
	Use:   "ovmf",
	Short: "Open Virtual Machine Firmware Management",
	Long:  `Manage and parse Open Virtual Machine Firmware (OVMF) variables.`,
}

var ovmfParseCmd = &cobra.Command{
	Use:   "parse [file]",
	Short: "Display OVMF variables",
	Long:  `Parses the specified OVMF_VARS.fd file and displays the UEFI variables in key-value format or JSON.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := "/usr/share/OVMF/OVMF_VARS_4M.fd" // Default path
		if len(args) > 0 {
			filename = args[0]
		}

		vars, err := hypervisor.ParseUEFIVars(filename)
		if err != nil {
			log.Fatalf("Error parsing OVMF variables: %v", err)
		}

		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			if len(vars) == 0 {
				fmt.Println("No UEFI variables found.")
				return
			}
			output, err := json.MarshalIndent(vars, "", "  ")
			if err != nil {
				log.Fatalf("Failed to marshal variables to JSON: %v", err)
			}
			fmt.Println(string(output))
			return
		}

		if len(vars) == 0 {
			fmt.Println("The vars file is empty or contains no UEFI variables.")
			return
		}

		fmt.Println("Extracted UEFI Variables:")
		for _, v := range vars {
			valueStr := v.Value
			if strings.TrimSpace(valueStr) == "" {
				valueStr = fmt.Sprintf("%x", v.Data)
			}
			fmt.Printf("Variable Name: %s\n", v.Name)
			fmt.Printf("Vendor GUID  : %s\n", formatGUID(v.VendorGUID))
			fmt.Printf("Attributes   : 0x%X\n", v.Attributes)
			fmt.Printf("Value        : %s\n\n", valueStr)
		}
	},
}

// formatGUID formats the EFI_GUID into a standard string representation.
func formatGUID(g hypervisor.EFI_GUID) string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}
