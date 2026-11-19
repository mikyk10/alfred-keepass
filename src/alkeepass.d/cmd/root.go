package cmd

import (
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{}

func init() {
	RootCmd.AddCommand(searchCmd)
	RootCmd.AddCommand(getCmd)
	RootCmd.AddCommand(passwordCmd)
	RootCmd.AddCommand(setPasswordCmd)
	RootCmd.AddCommand(deletePasswordCmd)
	RootCmd.AddCommand(unlockCmd)
	RootCmd.AddCommand(clipCmd)
	RootCmd.AddCommand(showCmd)
	RootCmd.AddCommand(attachmentExportCmd)
	RootCmd.AddCommand(clearClipboardCmd)
	RootCmd.AddCommand(keyAgentCmd)
	RootCmd.AddCommand(lockCmd)
}
