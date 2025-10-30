/*
Copyright © 2025 actions
*/
package main

import (
	"fmt"
	"math"
	"os"

	"github.com/actions/scaleset/examples/docker/app"
	"github.com/actions/scaleset/examples/docker/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configPath string

var cfg config.Config

var cmd = &cobra.Command{
	Use:   "docker-scaleset",
	Short: "Example CLI application scaling runners using Docker",
	Long: `This is an example CLI application that demonstrates how to scale
runners using Docker. It provides commands to manage and scale
Docker containers effectively.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if configPath != "" {
			viper.SetConfigFile(configPath)
			if err := viper.ReadInConfig(); err != nil {
				return fmt.Errorf("failed to read config file %q: %w", configPath, err)
			}
		}

		if err := viper.Unmarshal(&cfg); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}

		return app.Run(cmd.Context(), cfg)
	},
}

func init() {
	flags := cmd.PersistentFlags()
	flags.StringVarP(&configPath, "config", "c", "", "Path to the configuration file")
	flags.StringVar(&cfg.ConfigureURL, "url", "", "URL for configuration")
	flags.IntVar(&cfg.MaxRunners, "max-runners", math.MaxInt32, "Maximum number of runners")
	flags.IntVar(&cfg.MinRunners, "min-runners", 0, "Minimum number of runners")
	flags.StringVar(&cfg.ScaleSetName, "scale-set-name", "", "Name of the scale set")
	flags.StringVar(&cfg.RunnerGroup, "runner-group", "default", "Runner group name")
	flags.StringVar(&cfg.GitHubApp.AppID, "app-id", "", "Application ID")
	flags.Int64Var(&cfg.GitHubApp.AppInstallationID, "app-installation-id", 0, "Application installation ID")
	flags.StringVar(&cfg.GitHubApp.AppPrivateKey, "app-private-key", "", "Path to application private key")
	flags.StringVar(&cfg.Token, "token", "", "Authentication token")

	if err := viper.BindPFlags(flags); err != nil {
		panic(fmt.Errorf("failed to bind flags: %w", err))
	}
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v", err)
		os.Exit(1)
	}
}
