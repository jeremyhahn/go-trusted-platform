//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"gopkg.in/yaml.v3"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(1)
	}
	var a app.App
	if err := yaml.Unmarshal(data, &a); err != nil {
		fmt.Println("unmarshal:", err)
		os.Exit(1)
	}
	if a.NetworkConfig == nil {
		fmt.Println("NetworkConfig: nil")
		return
	}
	fmt.Printf("interfaces=%d bridges=%d bonds=%d\n",
		len(a.NetworkConfig.Interfaces), len(a.NetworkConfig.Bridges), len(a.NetworkConfig.Bonds))
	for i, b := range a.NetworkConfig.Bonds {
		fmt.Printf("  bond[%d]: name=%s iface=%v vlans=%d\n", i, b.Name, b.Interfaces, len(b.VLANs))
	}
}
