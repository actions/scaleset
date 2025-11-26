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
			expected  *gitHubConfig
		}{
			{
				configURL: "https://github.com/org/repo",
				expected: &gitHubConfig{
					scope:        gitHubScopeRepository,
					enterprise:   "",
					organization: "org",
					repository:   "repo",
					isHosted:     true,
				},
			},
			{
				configURL: "https://github.com/org/repo/",
				expected: &gitHubConfig{
					scope:        gitHubScopeRepository,
					enterprise:   "",
					organization: "org",
					repository:   "repo",
					isHosted:     true,
				},
			},
			{
				configURL: "https://github.com/org",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://github.com/enterprises/my-enterprise",
				expected: &gitHubConfig{
					scope:        gitHubScopeEnterprise,
					enterprise:   "my-enterprise",
					organization: "",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://github.com/enterprises/my-enterprise/",
				expected: &gitHubConfig{
					scope:        gitHubScopeEnterprise,
					enterprise:   "my-enterprise",
					organization: "",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://www.github.com/org",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://www.github.com/org/",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://github.localhost/org",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     true,
				},
			},
			{
				configURL: "https://my-ghes.com/org",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     false,
				},
			},
			{
				configURL: "https://my-ghes.com/org/",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     false,
				},
			},
			{
				configURL: "https://my-ghes.ghe.com/org/",
				expected: &gitHubConfig{
					scope:        gitHubScopeOrganization,
					enterprise:   "",
					organization: "org",
					repository:   "",
					isHosted:     true,
				},
			},
		}

		for _, test := range tests {
			t.Run(test.configURL, func(t *testing.T) {
				parsedURL, err := url.Parse(strings.Trim(test.configURL, "/"))
				require.NoError(t, err)
				test.expected.configURL = parsedURL

				cfg, err := parseGitHubConfigFromURL(test.configURL)
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
			_, err := parseGitHubConfigFromURL(u)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidGitHubConfigURL))
		}
	})
}

func TestGitHubConfig_GitHubAPIURL(t *testing.T) {
	t.Run("when hosted", func(t *testing.T) {
		config, err := parseGitHubConfigFromURL("https://github.com/org/repo")
		require.NoError(t, err)
		assert.True(t, config.isHosted)

		result := config.gitHubAPIURL("/some/path")
		assert.Equal(t, "https://api.github.com/some/path", result.String())
	})
	t.Run("when hosted with ghe.com", func(t *testing.T) {
		config, err := parseGitHubConfigFromURL("https://github.ghe.com/org/repo")
		require.NoError(t, err)
		assert.True(t, config.isHosted)

		result := config.gitHubAPIURL("/some/path")
		assert.Equal(t, "https://api.github.ghe.com/some/path", result.String())
	})
	t.Run("when not hosted", func(t *testing.T) {
		config, err := parseGitHubConfigFromURL("https://ghes.com/org/repo")
		require.NoError(t, err)
		assert.False(t, config.isHosted)

		result := config.gitHubAPIURL("/some/path")
		assert.Equal(t, "https://ghes.com/api/v3/some/path", result.String())
	})
	t.Run("when not hosted with ghe.com", func(t *testing.T) {
		os.Setenv("GITHUB_ACTIONS_FORCE_GHES", "1")
		defer os.Unsetenv("GITHUB_ACTIONS_FORCE_GHES")
		config, err := parseGitHubConfigFromURL("https://test.ghe.com/org/repo")
		require.NoError(t, err)
		assert.False(t, config.isHosted)

		result := config.gitHubAPIURL("/some/path")
		assert.Equal(t, "https://test.ghe.com/api/v3/some/path", result.String())
	})
}
