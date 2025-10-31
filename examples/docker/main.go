/*
Copyright © 2025 actions
*/
package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/actions/scaleset"
	"github.com/actions/scaleset/examples/docker/internal/app"
	"github.com/actions/scaleset/examples/docker/internal/config"
	"github.com/spf13/cobra"
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
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}

		return app.Run(ctx, cfg)
	},
}

func init() {
	flags := cmd.PersistentFlags()
	flags.StringVarP(&configPath, "config", "c", "", "Path to the configuration file")
	flags.StringVar(&cfg.ConfigureURL, "url", "", "URL for configuration")
	flags.IntVar(&cfg.MaxRunners, "max-runners", 10, "Maximum number of runners")
	flags.IntVar(&cfg.MinRunners, "min-runners", 0, "Minimum number of runners")
	flags.StringVar(&cfg.ScaleSetName, "scale-set-name", "", "Name of the scale set")
	flags.StringVar(&cfg.RunnerGroup, "runner-group", scaleset.DefaultRunnerGroup, "Runner group name")
	flags.StringVar(&cfg.GitHubApp.AppID, "app-id", "", "Application ID")
	flags.Int64Var(&cfg.GitHubApp.AppInstallationID, "app-installation-id", 0, "Application installation ID")
	flags.StringVar(&cfg.GitHubApp.AppPrivateKey, "app-private-key", "", "Path to application private key")
	flags.StringVar(&cfg.Token, "token", "", "Authentication token")
	flags.StringVar(&cfg.LogLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	flags.StringVar(&cfg.LogFormat, "log-format", "text", "Logging format (text, json). If invalid value is provided, defaults to no logs.")
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Command failed: %v", err)
		os.Exit(1)
	}
}
