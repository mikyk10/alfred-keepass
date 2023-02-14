package cmd

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{}

func init() {
	RootCmd.AddCommand(searchCmd)
	RootCmd.AddCommand(getCmd)
}
