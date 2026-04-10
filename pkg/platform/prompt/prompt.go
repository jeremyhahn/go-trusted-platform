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

package prompt

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"syscall"

	"github.com/fatih/color"
	"golang.org/x/term"
)

const (
	userPrompt = "trusted-platform> $ "
)

// PasswordReader is an interface for reading passwords from a terminal.
// This allows for dependency injection and testability.
type PasswordReader interface {
	ReadPassword(fd int) ([]byte, error)
}

// TermPasswordReader implements PasswordReader using the terminal package.
type TermPasswordReader struct{}

// ReadPassword reads a password from the terminal without echoing.
func (t *TermPasswordReader) ReadPassword(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// Prompter provides prompt functionality with dependency injection for testability.
type Prompter struct {
	reader         io.Reader
	writer         io.Writer
	passwordReader PasswordReader
	stdinFd        int
}

// PrompterOption is a functional option for configuring a Prompter.
type PrompterOption func(*Prompter)

// WithReader sets the input reader for the Prompter.
func WithReader(r io.Reader) PrompterOption {
	return func(p *Prompter) {
		p.reader = r
	}
}

// WithWriter sets the output writer for the Prompter.
func WithWriter(w io.Writer) PrompterOption {
	return func(p *Prompter) {
		p.writer = w
	}
}

// WithPasswordReader sets the password reader for the Prompter.
func WithPasswordReader(pr PasswordReader) PrompterOption {
	return func(p *Prompter) {
		p.passwordReader = pr
	}
}

// WithStdinFd sets the file descriptor for stdin.
func WithStdinFd(fd int) PrompterOption {
	return func(p *Prompter) {
		p.stdinFd = fd
	}
}

// NewPrompter creates a new Prompter with the given options.
func NewPrompter(opts ...PrompterOption) *Prompter {
	p := &Prompter{
		reader:         os.Stdin,
		writer:         os.Stdout,
		passwordReader: &TermPasswordReader{},
		stdinFd:        int(syscall.Stdin),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// PasswordPrompt prompts the user for a password without echoing the input.
func (p *Prompter) PasswordPrompt(message string) ([]byte, error) {
	if _, err := fmt.Fprintf(p.writer, "%s: \n", message); err != nil {
		return nil, &PromptWriteError{Message: message, Err: err}
	}
	if _, err := fmt.Fprint(p.writer, userPrompt); err != nil {
		return nil, &PromptWriteError{Message: message, Err: err}
	}
	password, err := p.passwordReader.ReadPassword(p.stdinFd)
	if err != nil {
		return nil, &PasswordReadError{Err: err}
	}
	if _, err := fmt.Fprintln(p.writer); err != nil {
		return nil, &PromptWriteError{Message: message, Err: err}
	}
	return password, nil
}

// SOPin prompts for the Security Officer PIN.
func (p *Prompter) SOPin() ([]byte, error) {
	return p.PasswordPrompt("Security Officer PIN")
}

// Pin prompts for the User PIN.
func (p *Prompter) Pin() ([]byte, error) {
	return p.PasswordPrompt("User PIN")
}

// KeyPassword prompts for a key password.
func (p *Prompter) KeyPassword() ([]byte, error) {
	return p.PasswordPrompt("Key Password")
}

// Prompt displays a message and reads a line of input.
func (p *Prompter) Prompt(message string) ([]byte, error) {
	reader := bufio.NewReader(p.reader)

	if _, err := fmt.Fprintf(p.writer, "%s: \n", message); err != nil {
		return nil, &PromptWriteError{Message: message, Err: err}
	}
	if _, err := fmt.Fprint(p.writer, userPrompt); err != nil {
		return nil, &PromptWriteError{Message: message, Err: err}
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, &PromptReadError{Err: err}
	}

	return []byte(response), nil
}

// NoOpPrompt reads a line of input without displaying a prompt.
func (p *Prompter) NoOpPrompt() ([]byte, error) {
	reader := bufio.NewReader(p.reader)
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, &PromptReadError{Err: err}
	}
	return []byte(response), nil
}

// PrintBanner prints the platform banner with the given version.
func PrintBanner(version string) {
	if _, err := color.New(color.FgGreen).Printf("Trusted Platform v%s\n\n", version); err != nil {
		fmt.Printf("Trusted Platform v%s\n\n", version)
	}
}

// defaultPrompter is the default prompter used by legacy functions.
// It is package-level to allow testing via dependency injection.
var defaultPrompter = NewPrompter()

// SetDefaultPrompter sets the default prompter used by legacy functions.
// This is primarily useful for testing.
func SetDefaultPrompter(p *Prompter) {
	defaultPrompter = p
}

// Legacy functions for backward compatibility.
// These use the default prompter and call log.Fatal on errors.

// PasswordPrompt prompts the user for a password without echoing.
// Deprecated: Use Prompter.PasswordPrompt instead for better error handling.
func PasswordPrompt(message string) []byte {
	result, err := defaultPrompter.PasswordPrompt(message)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// SOPin prompts for the Security Officer PIN.
// Deprecated: Use Prompter.SOPin instead for better error handling.
func SOPin() []byte {
	result, err := defaultPrompter.SOPin()
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// Pin prompts for the User PIN.
// Deprecated: Use Prompter.Pin instead for better error handling.
func Pin() []byte {
	result, err := defaultPrompter.Pin()
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// KeyPassword prompts for a key password.
// Deprecated: Use Prompter.KeyPassword instead for better error handling.
func KeyPassword() []byte {
	result, err := defaultPrompter.KeyPassword()
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// Prompt displays a message and reads a line of input.
// Deprecated: Use Prompter.Prompt instead for better error handling.
func Prompt(message string) []byte {
	result, err := defaultPrompter.Prompt(message)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

// NoOpPrompt reads a line of input without displaying a prompt.
// Deprecated: Use Prompter.NoOpPrompt instead for better error handling.
func NoOpPrompt() []byte {
	result, err := defaultPrompter.NoOpPrompt()
	if err != nil {
		log.Fatal(err)
	}
	return result
}
