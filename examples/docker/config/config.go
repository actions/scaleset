// Package config provides configuration structure and validation for the scaleset runner manager.
package config

import (
	"fmt"
	"net/url"

	"github.com/actions/scaleset"
)

type Config struct {
	ConfigureURL string
	MaxRunners   int
	MinRunners   int
	ScaleSetName string
	RunnerGroup  string
	GitHubApp    scaleset.GitHubAppAuth
	Token        string
	RunnerImage  string
}

func (c *Config) defaults() {
	if c.RunnerGroup == "" {
		c.RunnerGroup = "default"
	}
	if c.RunnerImage == "" {
		c.RunnerImage = "ghcr.io/actions/actions-runner:latest"
	}
}

func (c *Config) Validate() error {
	c.defaults()

	if _, err := url.ParseRequestURI(c.ConfigureURL); err != nil {
		return fmt.Errorf("invalid configure-url: %w", err)
	}

	appError := c.GitHubApp.Validate()
	if c.Token == "" && appError != nil {
		return fmt.Errorf("either token or app-id, app-installation-id, and app-private-key must be provided")
	}

	if c.ScaleSetName == "" {
		return fmt.Errorf("scale-set-name is required")
	}
	if c.MaxRunners < c.MinRunners {
		return fmt.Errorf("max-runners cannot be less than min-runners")
	}
	if c.RunnerGroup == "" {
		return fmt.Errorf("runner-group is required")
	}
	if c.RunnerImage == "" {
		return fmt.Errorf("runner-image is required")
	}
	return nil
}

func (c *Config) ActionsAuth() *scaleset.ActionsAuth {
	if err := c.GitHubApp.Validate(); err == nil {
		return &scaleset.ActionsAuth{
			App: &c.GitHubApp,
		}
	}

	return &scaleset.ActionsAuth{
		Token: c.Token,
	}
}
