package scaleset

import "context"

// TokenProvider supplies bearer tokens for GitHub API authentication.
// Implementations must be safe for concurrent use.
//
// The client consults the provider each time it (re-)authenticates against
// the GitHub API, so implementations can rotate short-lived credentials —
// for example GitHub App installation access tokens minted (or cached)
// outside the client — without the client being rebuilt.
//
// The token must be accepted at the scope of the client's config URL, and
// not every credential is valid at every scope:
//
//   - Enterprise (https://HOST/enterprises/NAME) requires a personal access
//     token with the manage_runners:enterprise scope. Today a GitHub App is
//     installed on an organization or a repository, never on an enterprise,
//     so no installation access token can be minted at this scope. Nothing
//     in the client enforces that: if GitHub ships enterprise-installable
//     Apps, their installation tokens flow through this seam unchanged.
//   - Organization (https://HOST/ORG) accepts a personal access token with
//     admin:org, or an installation access token from an App holding the
//     organization_self_hosted_runners permission.
//   - Repository (https://HOST/ORG/REPO) accepts a personal access token
//     with repo, or an installation access token from an App holding the
//     administration permission.
//
// Whatever is returned is sent verbatim as an Authorization: Bearer header
// for a single request; the client neither inspects nor caches it. A
// provider handing out expiring credentials therefore owns their renewal —
// which is the point of the seam, since renewal can then be shared across
// clients and processes rather than duplicated inside each one.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// tokenFuncProvider wraps a plain function as a TokenProvider.
type tokenFuncProvider struct {
	fn func(ctx context.Context) (string, error)
}

func (p *tokenFuncProvider) Token(ctx context.Context) (string, error) {
	return p.fn(ctx)
}

// TokenProviderFunc wraps a function as a TokenProvider.
func TokenProviderFunc(fn func(ctx context.Context) (string, error)) TokenProvider {
	return &tokenFuncProvider{fn: fn}
}
