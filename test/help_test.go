package test

import (
	"testing"

	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	assert "github.com/stretchr/testify/require"
)

func TestHelpCmd(t *testing.T) {
	t.Parallel()

	helpCmd := &cmd.Help{}

	assert.NoError(t, helpCmd.Init(nil, nil), "should init successfully")
	assert.NoError(t, helpCmd.Run(), "should run without error")
}
