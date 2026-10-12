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

package commands

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// flagClashes walks the command tree under root and reports every flag a
// command declares whose shorthand is already taken by a persistent flag of
// another name that the command inherits. Cobra merges inherited persistent
// flags into each command's flag set when the command is parsed, and a
// shorthand collision makes that merge panic, so the command crashes on every
// call, --help included. A flag that redeclares an inherited flag's name
// shadows it instead; the merge skips it and nothing crashes.
func flagClashes(root *cobra.Command) []string {
	var clashes []string

	var walk func(cmd *cobra.Command, inherited []*pflag.Flag)
	walk = func(cmd *cobra.Command, inherited []*pflag.Flag) {
		var own []*pflag.Flag
		collect := func(f *pflag.Flag) { own = append(own, f) }
		cmd.Flags().VisitAll(collect)
		cmd.PersistentFlags().VisitAll(collect)

		for _, f := range own {
			for _, g := range inherited {
				if f == g {
					continue
				}
				if f.Name != g.Name && f.Shorthand != "" && f.Shorthand == g.Shorthand {
					clashes = append(clashes, fmt.Sprintf("%s: --%s/-%s clashes with inherited --%s/-%s",
						cmd.CommandPath(), f.Name, f.Shorthand, g.Name, g.Shorthand))
				}
			}
		}

		next := append([]*pflag.Flag(nil), inherited...)
		cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) { next = append(next, f) })
		for _, child := range cmd.Commands() {
			walk(child, next)
		}
	}

	walk(root, nil)
	return clashes
}

// TestCommandTreeHasNoFlagClashes guards every platformctl verb against
// declaring a flag that collides with a global persistent flag (for example a
// local -v while --verbose/-v is global), which crashes the verb on every call.
func TestCommandTreeHasNoFlagClashes(t *testing.T) {
	for _, clash := range flagClashes(rootCmd) {
		t.Error(clash)
	}
}

func TestFlagClashesDetectsShorthandAndNameCollisions(t *testing.T) {
	newRoot := func() *cobra.Command {
		root := &cobra.Command{Use: "root"}
		root.PersistentFlags().BoolP("verbose", "v", false, "")
		root.PersistentFlags().StringP("output", "o", "", "")
		return root
	}

	t.Run("shorthand reused under another name", func(t *testing.T) {
		root := newRoot()
		child := &cobra.Command{Use: "get"}
		child.Flags().Uint64P("version", "v", 0, "")
		root.AddCommand(child)

		clashes := flagClashes(root)
		if len(clashes) != 1 {
			t.Fatalf("expected 1 clash, got %v", clashes)
		}
	})

	t.Run("shorthand reused below an intermediate command", func(t *testing.T) {
		root := newRoot()
		parent := &cobra.Command{Use: "kms"}
		grandchild := &cobra.Command{Use: "export"}
		grandchild.Flags().StringP("output-file", "o", "", "")
		parent.AddCommand(grandchild)
		root.AddCommand(parent)

		clashes := flagClashes(root)
		if len(clashes) != 1 {
			t.Fatalf("expected 1 clash, got %v", clashes)
		}
	})

	t.Run("shadowed names and distinct flags are allowed", func(t *testing.T) {
		root := newRoot()
		child := &cobra.Command{Use: "encrypt"}
		child.Flags().StringP("output", "o", "", "")
		child.Flags().Bool("verbose", false, "")
		child.Flags().StringP("key-id", "k", "", "")
		root.AddCommand(child)

		if clashes := flagClashes(root); len(clashes) != 0 {
			t.Fatalf("expected no clashes, got %v", clashes)
		}
	})
}
