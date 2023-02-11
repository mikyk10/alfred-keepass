package cmd

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	_ "embed"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var RootCmd = &cobra.Command{}

//go:embed default.toml
var defaultConfig []byte

func init() {

	// load configuration file
	execName := executableName()
	viper.SetConfigName(fmt.Sprintf(".%s", execName)) // name of config file (without extension)
	viper.SetConfigType("toml")                       // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("$HOME")                      // path to look for the config file in

	for {
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				// Config file not found; ignore error if desired
				println("WARN: config not found in pre-defined directories.")

				// create default config and re-read
				cur, _ := user.Current()
				f, err := os.OpenFile(filepath.Join(cur.HomeDir, "."+execName), os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					panic(err)
				}
				f.Write(defaultConfig)
				f.Close()
				continue
			} else {
				// Config file was found but another error was produced
				panic(fmt.Errorf("fatal error config file: %w", err))
			}
		}
		break
	}

	RootCmd.AddCommand(searchCmd)
	searchCmd.Flags().Bool("alfred", false, "Spits JSON string Alfred")
}

func executableName() string {
	path, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return filepath.Base(path)
}
