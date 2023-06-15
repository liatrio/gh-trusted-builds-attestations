package test

import (
	"testing"

	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	assert "github.com/stretchr/testify/require"
)

func TestVersionCmd(t *testing.T) {
	t.Parallel()

	versionCmd := cmd.VersionCmd()

	assert.NoError(t, versionCmd.Execute(), "should run without error")
}
