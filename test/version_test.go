package test

import (
	"testing"

	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	assert "github.com/stretchr/testify/require"
)

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	versionCmd := &cmd.Version{}

	assert.NoError(t, versionCmd.Init(nil, nil), "should init successfully")
	assert.NoError(t, versionCmd.Run(), "should run without error")
}
