package main

import (
	"os"

	"alkeepass/cmd"
)

func main() {
	// cobra has already reported the error (e.g. a wrong argument) on stderr;
	// the scripts calling the binary only need to see that it failed.
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
