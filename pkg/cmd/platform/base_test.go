package platform

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

func executeCommand(cmd *cobra.Command, args []string) string {

	b := new(bytes.Buffer)

	cmd.SetOut(b)
	cmd.SetErr(b)
	cmd.SetArgs(args)

	err := cmd.Execute()
	if err != nil {
		slog.Error(err.Error())
		return err.Error()
	}

	response := string(b.Bytes())
	fmt.Println(response)

	return response
}
