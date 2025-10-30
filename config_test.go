package scaleset

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubConfig(t *testing.T) {
	t.Run("when given a valid URL", func(t *testing.T) {
		tests := []struct {
			configURL string
			expected  *GitHubConfig
		}{
			{
				configURL: "https://github.com/org/repo",
				expected: &GitHubConfig{
					Scope:        GitHubScopeRepository,
					Enterprise:   "",
					Organization: "org",
					Repository:   "repo",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://github.com/org/repo/",
				expected: &GitHubConfig{
					Scope:        GitHubScopeRepository,
					Enterprise:   "",
					Organization: "org",
					Repository:   "repo",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://github.com/org",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://github.com/enterprises/my-enterprise",
				expected: &GitHubConfig{
					Scope:        GitHubScopeEnterprise,
					Enterprise:   "my-enterprise",
					Organization: "",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://github.com/enterprises/my-enterprise/",
				expected: &GitHubConfig{
					Scope:        GitHubScopeEnterprise,
					Enterprise:   "my-enterprise",
					Organization: "",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://www.github.com/org",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://www.github.com/org/",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://github.localhost/org",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     true,
				},
			},
			{
				configURL: "https://my-ghes.com/org",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     false,
				},
			},
			{
				configURL: "https://my-ghes.com/org/",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     false,
				},
			},
			{
				configURL: "https://my-ghes.ghe.com/org/",
				expected: &GitHubConfig{
					Scope:        GitHubScopeOrganization,
					Enterprise:   "",
					Organization: "org",
					Repository:   "",
					IsHosted:     true,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.configURL, func(t *testing.T) {
				parsedURL, err := url.Parse(strings.Trim(test.configURL, "/"))
				require.NoError(t, err)
				test.expected.ConfigURL = parsedURL

				cfg, err := ParseGitHubConfigFromURL(test.configURL)
				require.NoError(t, err)
				assert.Equal(t, test.expected, cfg)
			})
		}
	})

	t.Run("when given an invalid URL", func(t *testing.T) {
		invalidURLs := []string{
			"https://github.com/",
			"https://github.com",
			"https://github.com/some/random/path",
		}

		for _, u := range invalidURLs {
			_, err := ParseGitHubConfigFromURL(u)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidGitHubConfigURL))
		}
	})
}

func TestGitHubConfig_GitHubAPIURL(t *testing.T) {
	t.Run("when hosted", func(t *testing.T) {
		config, err := ParseGitHubConfigFromURL("https://github.com/org/repo")
		require.NoError(t, err)
		assert.True(t, config.IsHosted)

		result := config.GitHubAPIURL("/some/path")
		assert.Equal(t, "https://api.github.com/some/path", result.String())
	})
	t.Run("when hosted with ghe.com", func(t *testing.T) {
		config, err := ParseGitHubConfigFromURL("https://github.ghe.com/org/repo")
		require.NoError(t, err)
		assert.True(t, config.IsHosted)

		result := config.GitHubAPIURL("/some/path")
		assert.Equal(t, "https://api.github.ghe.com/some/path", result.String())
	})
	t.Run("when not hosted", func(t *testing.T) {
		config, err := ParseGitHubConfigFromURL("https://ghes.com/org/repo")
		require.NoError(t, err)
		assert.False(t, config.IsHosted)

		result := config.GitHubAPIURL("/some/path")
		assert.Equal(t, "https://ghes.com/api/v3/some/path", result.String())
	})
	t.Run("when not hosted with ghe.com", func(t *testing.T) {
		os.Setenv("GITHUB_ACTIONS_FORCE_GHES", "1")
		defer os.Unsetenv("GITHUB_ACTIONS_FORCE_GHES")
		config, err := ParseGitHubConfigFromURL("https://test.ghe.com/org/repo")
		require.NoError(t, err)
		assert.False(t, config.IsHosted)

		result := config.GitHubAPIURL("/some/path")
		assert.Equal(t, "https://test.ghe.com/api/v3/some/path", result.String())
	})
}
