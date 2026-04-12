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

package kms

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrBatchInputRequired is returned when batch input is required
type ErrBatchInputRequired struct{}

func (e ErrBatchInputRequired) Error() string {
	return "batch operation requires input (use --input flag or provide items via stdin)"
}

// ErrInvalidBatchFormat is returned when batch input format is invalid
type ErrInvalidBatchFormat struct {
	Reason string
}

func (e ErrInvalidBatchFormat) Error() string {
	return fmt.Sprintf("invalid batch input format: %s", e.Reason)
}

// ErrBatchOperationFailed is returned when a batch operation fails
type ErrBatchOperationFailed struct {
	Operation string
	Err       error
}

func (e ErrBatchOperationFailed) Error() string {
	return fmt.Sprintf("batch %s operation failed: %v", e.Operation, e.Err)
}

func (e ErrBatchOperationFailed) Unwrap() error {
	return e.Err
}

// BatchEncryptInputItem represents an input item for batch encryption
type BatchEncryptInputItem struct {
	ItemID    string `json:"item_id,omitempty"`
	Plaintext string `json:"plaintext"`
	Context   string `json:"context,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}

// BatchDecryptInputItem represents an input item for batch decryption
type BatchDecryptInputItem struct {
	ItemID     string `json:"item_id,omitempty"`
	Ciphertext string `json:"ciphertext"`
	Context    string `json:"context,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// BatchEncryptOutputItem represents an output item for batch encryption
type BatchEncryptOutputItem struct {
	ItemID     string `json:"item_id" yaml:"item_id"`
	Status     string `json:"status" yaml:"status"`
	Ciphertext string `json:"ciphertext,omitempty" yaml:"ciphertext,omitempty"`
	Nonce      string `json:"nonce,omitempty" yaml:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty" yaml:"key_version,omitempty"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
}

// BatchDecryptOutputItem represents an output item for batch decryption
type BatchDecryptOutputItem struct {
	ItemID     string `json:"item_id" yaml:"item_id"`
	Status     string `json:"status" yaml:"status"`
	Plaintext  string `json:"plaintext,omitempty" yaml:"plaintext,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty" yaml:"key_version,omitempty"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
}

// batchEncryptFlags contains flags for batch encrypt command
type batchEncryptFlags struct {
	keyID     string
	inputPath string
	jsonInput bool
}

// batchDecryptFlags contains flags for batch decrypt command
type batchDecryptFlags struct {
	keyID     string
	inputPath string
	jsonInput bool
}

// newCryptoBatchCommand creates the batch operations command group
func newCryptoBatchCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Batch cryptographic operations",
		Long: `Perform multiple encrypt or decrypt operations in a single request.

Batch operations are more efficient than individual requests when processing
multiple items. All operations use the same key.

Input format (JSON array):
  Encrypt: [{"plaintext": "data1"}, {"plaintext": "data2", "context": "ctx", "item_id": "id1"}]
  Decrypt: [{"ciphertext": "base64", "nonce": "base64"}, {"ciphertext": "base64", "context": "ctx"}]

Examples:
  # Batch encrypt from JSON file
  platformctl kms crypto batch encrypt --key-id mykey --input items.json

  # Batch encrypt from stdin
  echo '[{"plaintext": "secret1"}, {"plaintext": "secret2"}]' | platformctl kms crypto batch encrypt --key-id mykey

  # Batch decrypt
  platformctl kms crypto batch decrypt --key-id mykey --input encrypted.json`,
	}

	cmd.AddCommand(newBatchEncryptCommand(getFlags))
	cmd.AddCommand(newBatchDecryptCommand(getFlags))

	return cmd
}

// newBatchEncryptCommand creates the batch encrypt subcommand
func newBatchEncryptCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &batchEncryptFlags{}

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Batch encrypt multiple items",
		Long: `Encrypt multiple plaintext items in a single request.

Input should be a JSON array of objects with 'plaintext' and optional fields:
  - item_id: Client-provided identifier for correlation (auto-generated if not provided)
  - plaintext: The data to encrypt (required, will be UTF-8 encoded)
  - context: Additional authenticated data (AAD)
  - nonce: Base64-encoded nonce (auto-generated if not provided)

Example input:
[
  {"plaintext": "secret1"},
  {"plaintext": "secret2", "context": "additional-data", "item_id": "my-item"}
]

Examples:
  # Batch encrypt from JSON file
  platformctl kms crypto batch encrypt --key-id mykey --input items.json

  # Batch encrypt from stdin (JSON format)
  echo '[{"plaintext": "a"}, {"plaintext": "b"}]' | platformctl kms crypto batch encrypt --key-id mykey

  # Output as JSON
  platformctl kms crypto batch encrypt --key-id mykey --input items.json -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runBatchEncrypt(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "encryption key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().BoolVar(&cmdFlags.jsonInput, "json", true, "input is JSON format")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// newBatchDecryptCommand creates the batch decrypt subcommand
func newBatchDecryptCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &batchDecryptFlags{}

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Batch decrypt multiple items",
		Long: `Decrypt multiple ciphertext items in a single request.

Input should be a JSON array of objects with 'ciphertext' and optional fields:
  - item_id: Client-provided identifier for correlation
  - ciphertext: Base64-encoded encrypted data (required)
  - context: Additional authenticated data (AAD) used during encryption
  - nonce: Base64-encoded nonce used during encryption
  - key_version: Key version used during encryption (0 for latest)

Example input:
[
  {"ciphertext": "base64-encoded-data", "nonce": "base64-nonce"},
  {"ciphertext": "base64-encoded-data", "context": "additional-data", "item_id": "my-item"}
]

Examples:
  # Batch decrypt from JSON file
  platformctl kms crypto batch decrypt --key-id mykey --input encrypted.json

  # Batch decrypt from stdin
  cat encrypted.json | platformctl kms crypto batch decrypt --key-id mykey

  # Output as JSON
  platformctl kms crypto batch decrypt --key-id mykey --input encrypted.json -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runBatchDecrypt(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "", "decryption key ID (required)")
	cmd.Flags().StringVarP(&cmdFlags.inputPath, "input", "i", "", "input file path")
	cmd.Flags().BoolVar(&cmdFlags.jsonInput, "json", true, "input is JSON format")

	if err := cmd.MarkFlagRequired("key-id"); err != nil {
		panic(fmt.Sprintf("failed to mark key-id flag required: %v", err))
	}

	return cmd
}

// runBatchEncrypt executes the batch encrypt operation
func runBatchEncrypt(flags *cli.CommonFlags, cmdFlags *batchEncryptFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Read input data
	inputData, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return ErrBatchInputRequired{}
	}

	// Parse JSON input
	var inputItems []BatchEncryptInputItem
	if err := json.Unmarshal(inputData, &inputItems); err != nil {
		return ErrInvalidBatchFormat{Reason: err.Error()}
	}

	if len(inputItems) == 0 {
		return ErrInvalidBatchFormat{Reason: "empty input array"}
	}

	// Build SDK request items
	items := make([]*kmssvc.BatchEncryptItemInput, 0, len(inputItems))
	for i, input := range inputItems {
		item := &kmssvc.BatchEncryptItemInput{
			ItemID:    input.ItemID,
			Plaintext: []byte(input.Plaintext),
		}

		// Auto-generate item ID if not provided
		if item.ItemID == "" {
			item.ItemID = fmt.Sprintf("item-%d", i)
		}

		// Parse context if provided
		if input.Context != "" {
			item.Context = []byte(input.Context)
		}

		// Parse nonce if provided (base64 encoded)
		if input.Nonce != "" {
			nonceBytes, err := base64.StdEncoding.DecodeString(input.Nonce)
			if err != nil {
				return ErrInvalidBase64{Field: fmt.Sprintf("nonce for item %s", item.ItemID), Err: err}
			}
			item.Nonce = nonceBytes
		}

		items = append(items, item)
	}

	ctx := base.Context()
	resp, err := sdkClient.BatchEncryptDomain(ctx, cmdFlags.keyID, items)
	if err != nil {
		return ErrBatchOperationFailed{Operation: "encrypt", Err: err}
	}

	printer := base.Printer()

	// Build output items
	outputItems := make([]BatchEncryptOutputItem, 0, len(resp.Results))
	for _, result := range resp.Results {
		output := BatchEncryptOutputItem{
			ItemID:     result.ItemID,
			KeyVersion: result.KeyVersion,
		}

		if result.Success {
			output.Status = "success"
			output.Ciphertext = base64.StdEncoding.EncodeToString(result.Ciphertext)
			output.Nonce = base64.StdEncoding.EncodeToString(result.Nonce)
		} else {
			output.Status = "failed"
			output.Error = result.Message
		}

		outputItems = append(outputItems, output)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID        string                   `json:"key_id" yaml:"key_id"`
			SuccessCount int32                    `json:"success_count" yaml:"success_count"`
			FailureCount int32                    `json:"failure_count" yaml:"failure_count"`
			Timestamp    string                   `json:"timestamp" yaml:"timestamp"`
			Results      []BatchEncryptOutputItem `json:"results" yaml:"results"`
		}{
			KeyID:        resp.KeyID,
			SuccessCount: resp.SuccessCount,
			FailureCount: resp.FailureCount,
			Timestamp:    formatTimestamp(resp.Timestamp),
			Results:      outputItems,
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Batch encryption completed: %d succeeded, %d failed",
			resp.SuccessCount, resp.FailureCount))
		printer.PrintKeyValue("Key ID", resp.KeyID)
		printer.PrintKeyValue("Timestamp", formatTimestamp(resp.Timestamp))

		table := cli.NewTableData("Item ID", "Status", "Ciphertext", "Nonce", "Key Version")
		for _, item := range outputItems {
			ciphertext := item.Ciphertext
			if len(ciphertext) > 32 {
				ciphertext = ciphertext[:32] + "..."
			}
			nonce := item.Nonce
			if len(nonce) > 24 {
				nonce = nonce[:24] + "..."
			}

			status := item.Status
			if item.Error != "" {
				status = fmt.Sprintf("%s: %s", status, item.Error)
			}

			table.AddRow(
				item.ItemID,
				status,
				ciphertext,
				nonce,
				fmt.Sprintf("%d", item.KeyVersion),
			)
		}
		return printer.Print(table)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runBatchDecrypt executes the batch decrypt operation
func runBatchDecrypt(flags *cli.CommonFlags, cmdFlags *batchDecryptFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := kmssvc.NewClientFromGRPC(base.Client().KMS())

	// Read input data
	inputData, err := readInputData(cmdFlags.inputPath)
	if err != nil {
		return ErrBatchInputRequired{}
	}

	// Parse JSON input
	var inputItems []BatchDecryptInputItem
	if err := json.Unmarshal(inputData, &inputItems); err != nil {
		return ErrInvalidBatchFormat{Reason: err.Error()}
	}

	if len(inputItems) == 0 {
		return ErrInvalidBatchFormat{Reason: "empty input array"}
	}

	// Build SDK request items
	items := make([]*kmssvc.BatchDecryptItemInput, 0, len(inputItems))
	for i, input := range inputItems {
		item := &kmssvc.BatchDecryptItemInput{
			ItemID:     input.ItemID,
			KeyVersion: input.KeyVersion,
		}

		// Auto-generate item ID if not provided
		if item.ItemID == "" {
			item.ItemID = fmt.Sprintf("item-%d", i)
		}

		// Parse ciphertext (base64 encoded)
		if input.Ciphertext == "" {
			return ErrInvalidBatchFormat{Reason: fmt.Sprintf("missing ciphertext for item %s", item.ItemID)}
		}
		ciphertext, err := base64.StdEncoding.DecodeString(input.Ciphertext)
		if err != nil {
			return ErrInvalidBase64{Field: fmt.Sprintf("ciphertext for item %s", item.ItemID), Err: err}
		}
		item.Ciphertext = ciphertext

		// Parse context if provided
		if input.Context != "" {
			item.Context = []byte(input.Context)
		}

		// Parse nonce if provided (base64 encoded)
		if input.Nonce != "" {
			nonceBytes, err := base64.StdEncoding.DecodeString(input.Nonce)
			if err != nil {
				return ErrInvalidBase64{Field: fmt.Sprintf("nonce for item %s", item.ItemID), Err: err}
			}
			item.Nonce = nonceBytes
		}

		items = append(items, item)
	}

	ctx := base.Context()
	resp, err := sdkClient.BatchDecryptDomain(ctx, cmdFlags.keyID, items)
	if err != nil {
		return ErrBatchOperationFailed{Operation: "decrypt", Err: err}
	}

	printer := base.Printer()

	// Build output items
	outputItems := make([]BatchDecryptOutputItem, 0, len(resp.Results))
	for _, result := range resp.Results {
		output := BatchDecryptOutputItem{
			ItemID:     result.ItemID,
			KeyVersion: result.KeyVersion,
		}

		if result.Success {
			output.Status = "success"
			output.Plaintext = string(result.Plaintext)
		} else {
			output.Status = "failed"
			output.Error = result.Message
		}

		outputItems = append(outputItems, output)
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := struct {
			KeyID        string                   `json:"key_id" yaml:"key_id"`
			SuccessCount int32                    `json:"success_count" yaml:"success_count"`
			FailureCount int32                    `json:"failure_count" yaml:"failure_count"`
			Timestamp    string                   `json:"timestamp" yaml:"timestamp"`
			Results      []BatchDecryptOutputItem `json:"results" yaml:"results"`
		}{
			KeyID:        resp.KeyID,
			SuccessCount: resp.SuccessCount,
			FailureCount: resp.FailureCount,
			Timestamp:    formatTimestamp(resp.Timestamp),
			Results:      outputItems,
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Batch decryption completed: %d succeeded, %d failed",
			resp.SuccessCount, resp.FailureCount))
		printer.PrintKeyValue("Key ID", resp.KeyID)
		printer.PrintKeyValue("Timestamp", formatTimestamp(resp.Timestamp))

		table := cli.NewTableData("Item ID", "Status", "Plaintext", "Key Version")
		for _, item := range outputItems {
			plaintext := item.Plaintext
			if len(plaintext) > 48 {
				plaintext = plaintext[:48] + "..."
			}

			status := item.Status
			if item.Error != "" {
				status = fmt.Sprintf("%s: %s", status, item.Error)
			}

			table.AddRow(
				item.ItemID,
				status,
				plaintext,
				fmt.Sprintf("%d", item.KeyVersion),
			)
		}
		return printer.Print(table)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
