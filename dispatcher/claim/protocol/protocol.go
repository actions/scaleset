// Package protocol holds the messages exchanged between ci-dispatcher and
// ci-runner-agent. It has no dependency so the agent binary stays small.
package protocol

// Preflight asks the agent of a warm pod to prepare the language cache of
// the repository it was given.
type Preflight struct {
	Root       string `json:"root"`
	ServerNode string `json:"serverNode"`
	Marker     string `json:"marker,omitempty"`
}

// Payload is what an agent receives from GET /v1/claim.
type Payload struct {
	JITConfig string            `json:"jitConfig"`
	Repo      string            `json:"repo"`
	Env       map[string]string `json:"env,omitempty"`
	Preflight *Preflight        `json:"preflight,omitempty"`
	StateDir  string            `json:"stateDir,omitempty"`
}
