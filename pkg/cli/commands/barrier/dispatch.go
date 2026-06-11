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

// dispatch.go holds the pure-dispatch core of every barrier verb. The
// outer runXxx handlers open the SDK connection via cli.NewBaseCommand
// (which dials platformd + quicbaasd) and then delegate to the
// dispatchXxx function. The split lets tests exercise the
// validation -> RPC -> rendering pipeline without dialing a daemon.
package barrier

import (
	"context"
	"fmt"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// dispatcher bundles the ingredients dispatchXxx functions need to do
// their work: the QuicBaaS-backed barrier client, the cancellation
// context, and the output sink. Bundling them keeps dispatchXxx
// signatures tight and testable.
type dispatcher struct {
	Client  quicbaassdk.QRDBBarrierClient
	Ctx     context.Context
	Output  cli.OutputFormat
	Printer *cli.Printer
}

// dispatchInit performs the BarrierInitialize RPC and renders the OK
// summary.
func dispatchInit(d *dispatcher, f *initFlags) error {
	req := &quicbaassdk.QRDBBarrierInitializeRequest{
		Secret:          f.secret,
		BarrierStrategy: f.strategy,
		SOPin:           f.soPin,
		UserPin:         f.userPin,
	}
	if err := d.Client.BarrierInitialize(d.Ctx, req); err != nil {
		return ErrBarrierInitFailed{Err: err}
	}
	return renderInitOKDispatch(d, f.strategy)
}

// renderInitOKDispatch renders the post-init OK message.
func renderInitOKDispatch(d *dispatcher, strategy string) error {
	type result struct {
		OK       bool   `json:"ok" yaml:"ok"`
		Strategy string `json:"strategy" yaml:"strategy"`
	}
	res := result{OK: true, Strategy: strategy}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(res)
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier initialized successfully")
		d.Printer.PrintKeyValue("Strategy", strategy)
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchInitShamir performs the BarrierInitializeShamir RPC and
// renders the shares.
func dispatchInitShamir(d *dispatcher, f *initShamirFlags) error {
	req := &quicbaassdk.QRDBBarrierInitializeShamirRequest{
		Secret:      f.secret,
		Threshold:   f.threshold,
		TotalShares: f.total,
		SOPin:       f.soPin,
		UserPin:     f.userPin,
	}
	resp, err := d.Client.BarrierInitializeShamir(d.Ctx, req)
	if err != nil {
		return ErrBarrierInitShamirFailed{Err: err}
	}
	if resp == nil {
		resp = &quicbaassdk.QRDBBarrierInitializeShamirResponse{}
	}
	return renderInitShamirDispatch(d, resp)
}

// renderInitShamirDispatch renders the init-shamir response.
func renderInitShamirDispatch(d *dispatcher, resp *quicbaassdk.QRDBBarrierInitializeShamirResponse) error {
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(resp)
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier initialized successfully (Shamir)")
		d.Printer.PrintKeyValue("Threshold", fmt.Sprintf("%d", resp.Threshold))
		d.Printer.PrintKeyValue("Total Shares", fmt.Sprintf("%d", resp.TotalShares))
		if resp.ShareCount > 0 {
			d.Printer.PrintKeyValue("Share Count", fmt.Sprintf("%d", resp.ShareCount))
			d.Printer.PrintInfo("Shares are sealed to enrolled Security Officers. Use barrier share claim to retrieve individual shares.")
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchStatus performs the BarrierStatus RPC and renders the
// response.
func dispatchStatus(d *dispatcher) error {
	resp, err := d.Client.BarrierStatus(d.Ctx)
	if err != nil {
		return ErrBarrierStatusFailed{Err: err}
	}
	if resp == nil {
		resp = &quicbaassdk.QRDBBarrierStatusResponse{}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(resp)
	case cli.OutputFormatTable, "":
		d.Printer.PrintKeyValue("Sealed", fmt.Sprintf("%v", resp.Sealed))
		if resp.Strategy != "" {
			d.Printer.PrintKeyValue("Strategy", resp.Strategy)
		}
		d.Printer.PrintKeyValue("Hardware Backed", fmt.Sprintf("%v", resp.HardwareBacked))
		if resp.InitializedAt != "" {
			d.Printer.PrintKeyValue("Initialized At", resp.InitializedAt)
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchUnseal performs the BarrierUnseal RPC.
func dispatchUnseal(d *dispatcher, secret string) error {
	if err := d.Client.BarrierUnseal(d.Ctx, &quicbaassdk.QRDBBarrierUnsealRequest{Secret: secret}); err != nil {
		return ErrBarrierUnsealFailed{Err: err}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(map[string]bool{"ok": true})
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier unsealed successfully")
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchUnsealShares performs the batch BarrierUnsealWithShares RPC.
func dispatchUnsealShares(d *dispatcher, shares []string) error {
	if err := d.Client.BarrierUnsealWithShares(d.Ctx, &quicbaassdk.QRDBBarrierUnsealSharesRequest{Shares: shares}); err != nil {
		return ErrBarrierUnsealSharesFailed{Err: err}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(map[string]any{"ok": true, "shares_submitted": len(shares)})
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier unsealed successfully")
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchSeal performs the BarrierSeal RPC.
func dispatchSeal(d *dispatcher) error {
	if err := d.Client.BarrierSeal(d.Ctx); err != nil {
		return ErrBarrierSealFailed{Err: err}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(map[string]bool{"ok": true, "sealed": true})
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier sealed successfully")
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchRekey performs the BarrierRekey RPC.
func dispatchRekey(d *dispatcher, f *rekeyFlags) error {
	req := &quicbaassdk.QRDBBarrierRekeyRequest{
		SOPin:     f.soPin,
		Threshold: f.threshold,
		Total:     f.total,
	}
	resp, err := d.Client.BarrierRekey(d.Ctx, req)
	if err != nil {
		return ErrBarrierRekeyFailed{Err: err}
	}
	if resp == nil {
		resp = &quicbaassdk.QRDBBarrierRekeyResponse{}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(resp)
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier rekeyed successfully")
		if resp.Threshold > 0 || resp.TotalShares > 0 {
			d.Printer.PrintKeyValue("Threshold", fmt.Sprintf("%d", resp.Threshold))
			d.Printer.PrintKeyValue("Total Shares", fmt.Sprintf("%d", resp.TotalShares))
		}
		if resp.ShareCount > 0 {
			d.Printer.PrintKeyValue("Share Count", fmt.Sprintf("%d", resp.ShareCount))
			d.Printer.PrintInfo("New shares are sealed to enrolled Security Officers. Use barrier share claim to retrieve individual shares.")
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchRecoveryGenerate performs BarrierGenerateRecoveryKeys.
func dispatchRecoveryGenerate(d *dispatcher, f *recoveryGenerateFlags) error {
	req := &quicbaassdk.QRDBBarrierGenerateRecoveryKeysRequest{
		Threshold: f.threshold,
		Total:     f.total,
		SOPin:     f.soPin,
	}
	resp, err := d.Client.BarrierGenerateRecoveryKeys(d.Ctx, req)
	if err != nil {
		return ErrBarrierRecoveryGenerateFailed{Err: err}
	}
	if resp == nil {
		resp = &quicbaassdk.QRDBBarrierRecoveryKeysResponse{}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(resp)
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Recovery shares generated")
		d.Printer.PrintKeyValue("Threshold", fmt.Sprintf("%d", resp.Threshold))
		d.Printer.PrintKeyValue("Total", fmt.Sprintf("%d", resp.Total))
		if resp.ShareCount > 0 {
			d.Printer.PrintKeyValue("Share Count", fmt.Sprintf("%d", resp.ShareCount))
			d.Printer.PrintInfo("Recovery shares are sealed to enrolled Recovery Officers. Use barrier share claim to retrieve individual shares.")
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// dispatchRecoveryRecover performs BarrierRecoverWithKeys.
func dispatchRecoveryRecover(d *dispatcher, shares []string) error {
	if err := d.Client.BarrierRecoverWithKeys(d.Ctx, &quicbaassdk.QRDBBarrierRecoverWithKeysRequest{Keys: shares}); err != nil {
		return ErrBarrierRecoveryRecoverFailed{Err: err}
	}
	switch d.Output {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return d.Printer.Print(map[string]any{"ok": true, "shares_submitted": len(shares)})
	case cli.OutputFormatTable, "":
		d.Printer.PrintSuccess("Barrier recovered successfully")
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(d.Output)}
	}
}

// newDispatcherFromBase builds a dispatcher from a BaseCommand using
// the supplied barrier client. It's the canonical wiring used by the
// outer runXxx handlers.
func newDispatcherFromBase(base *cli.BaseCommand, bc quicbaassdk.QRDBBarrierClient) *dispatcher {
	return &dispatcher{
		Client:  bc,
		Ctx:     base.Context(),
		Output:  base.Flags().OutputFormat,
		Printer: base.Printer(),
	}
}
