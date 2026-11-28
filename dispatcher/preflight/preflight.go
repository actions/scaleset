// Package preflight holds the language cache preparation script, shared by
// the init container of cold pods and by ci-runner-agent for warm pods.
package preflight

import _ "embed"

// Script prepares and probes the per-repository language cache.
//
//go:embed preflight.sh
var Script string
