package scaleset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserAgentInfoString(t *testing.T) {
	userAgentInfo := UserAgentInfo{
		System:     "actions-runner-controller",
		Version:    "0.1.0",
		CommitSHA:  "1234567890abcdef",
		ScaleSetID: 10,
		HasProxy:   true,
		Subsystem:  "test",
	}

	userAgent := userAgentInfo.String()
	expectedProduct := "actions-runner-controller/0.1.0 (1234567890abcdef; test)"
	assert.Contains(t, userAgent, expectedProduct)
	expectedScaleSet := "ScaleSetID/10 (Proxy/enabled)"
	assert.Contains(t, userAgent, expectedScaleSet)
}
