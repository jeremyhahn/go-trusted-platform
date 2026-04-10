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

package deployer

import (
	"bytes"
	"strings"
	"text/template"
)

// CiscoAppHostingParams holds the parameters for rendering Cisco IOS-XE
// app-hosting CLI templates.
type CiscoAppHostingParams struct {
	// AppID is the app-hosting application identifier (e.g., "platform-pxeboot").
	AppID string

	// VLANs are the VLAN IDs to trunk on the app vNIC.
	VLANs []int

	// GuestInterface is the guest interface number (typically 0).
	GuestInterface int

	// GuestIP is the IP address assigned to the container.
	GuestIP string

	// GuestNetmask is the subnet mask for the container IP.
	GuestNetmask string

	// ImageFile is the container tar filename on flash (e.g., "platform-pxeboot.tar").
	ImageFile string

	// RunOpts are Docker run options passed to the app-resource docker config.
	RunOpts []string
}

// ciscoConfigTemplate renders the IOS-XE app-hosting configuration block.
// This is entered in config mode on the router.
var ciscoConfigTemplate = `app-hosting appid {{.AppID}}
 app-vnic AppGigabitEthernet trunk
{{- range .VLANs}}
  vlan {{.}} guest-interface {{$.GuestInterface}}
{{- end}}
{{- if and .GuestIP .GuestNetmask}}
   guest-ipaddress {{.GuestIP}} netmask {{.GuestNetmask}}
{{- end}}
{{- if .RunOpts}}
 app-resource docker
{{- range $i, $opt := .RunOpts}}
  run-opts {{add $i 1}} "{{$opt}}"
{{- end}}
{{- end}}`

// ciscoInstallTemplate renders the install, activate, and start exec-mode commands.
var ciscoInstallTemplate = `app-hosting install appid {{.AppID}} package flash:{{.ImageFile}}
app-hosting activate appid {{.AppID}}
app-hosting start appid {{.AppID}}`

// ciscoTeardownTemplate renders the stop, deactivate, uninstall, and remove commands.
var ciscoTeardownTemplate = `app-hosting stop appid {{.AppID}}
app-hosting deactivate appid {{.AppID}}
app-hosting uninstall appid {{.AppID}}
no app-hosting appid {{.AppID}}`

// templateFuncMap provides helper functions for the CLI templates.
var templateFuncMap = template.FuncMap{
	"add": func(a, b int) int { return a + b },
}

// RenderCiscoConfig renders the app-hosting configuration commands from
// the given parameters.
func RenderCiscoConfig(params *CiscoAppHostingParams) (string, error) {
	tmpl, err := template.New("cisco-config").Funcs(templateFuncMap).Parse(ciscoConfigTemplate)
	if err != nil {
		return "", ErrTemplateRender{Name: "cisco-config", Cause: err}
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", ErrTemplateRender{Name: "cisco-config", Cause: err}
	}
	return buf.String(), nil
}

// RenderCiscoInstall renders the install, activate, and start exec-mode commands.
func RenderCiscoInstall(params *CiscoAppHostingParams) (string, error) {
	tmpl, err := template.New("cisco-install").Parse(ciscoInstallTemplate)
	if err != nil {
		return "", ErrTemplateRender{Name: "cisco-install", Cause: err}
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", ErrTemplateRender{Name: "cisco-install", Cause: err}
	}
	return buf.String(), nil
}

// RenderCiscoTeardown renders the stop, deactivate, uninstall, and remove commands.
func RenderCiscoTeardown(params *CiscoAppHostingParams) (string, error) {
	tmpl, err := template.New("cisco-teardown").Parse(ciscoTeardownTemplate)
	if err != nil {
		return "", ErrTemplateRender{Name: "cisco-teardown", Cause: err}
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", ErrTemplateRender{Name: "cisco-teardown", Cause: err}
	}
	return buf.String(), nil
}

// RenderCiscoDeployPlan renders the complete deployment CLI commands for
// dry-run inspection. It combines the config-mode and exec-mode commands
// into a single annotated output.
func RenderCiscoDeployPlan(provisioningGateway string, provisioningVLAN int) (string, error) {
	params := &CiscoAppHostingParams{
		AppID:          DefaultCiscoAppID,
		VLANs:          []int{provisioningVLAN},
		GuestInterface: 0,
		GuestIP:        provisioningGateway,
		GuestNetmask:   "255.255.255.0",
		ImageFile:      DefaultCiscoImageFile,
		RunOpts:        []string{"-v $(APP_DATA):/data"},
	}

	configCmds, err := RenderCiscoConfig(params)
	if err != nil {
		return "", err
	}

	installCmds, err := RenderCiscoInstall(params)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	sb.WriteString("! === App-Hosting Configuration (config mode) ===\n")
	sb.WriteString("configure terminal\n")
	sb.WriteString(configCmds)
	sb.WriteString("\nend\n")
	sb.WriteString("\n! === Install / Activate / Start (exec mode) ===\n")
	sb.WriteString(installCmds)
	sb.WriteString("\n")

	return sb.String(), nil
}
