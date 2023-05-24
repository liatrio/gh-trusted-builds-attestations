package cmd

import (
	"context"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
)

type GitHubPullRequest struct {
	ctx      context.Context
	opts     *config.GitHubPullRequestCommandOptions
	attestor *attestors.GitHubPullRequestAttestor
}

func (g *GitHubPullRequest) Is(s string) bool {
	return "github-pull-request" == s
}

func (g *GitHubPullRequest) Run() error {
	return g.attestor.Attest(g.ctx, g.opts)
}

func (g *GitHubPullRequest) Init(ctx context.Context, flags []string) error {
	g.ctx = ctx

	opts := config.NewGitHubPullRequestCommandOptions()
	err := opts.Parse(flags)
	if err != nil {
		return err
	}
	g.opts = opts

	attestor, err := attestors.NewGitHubPullRequestAttestor(ctx, opts)
	if err != nil {
		return err
	}

	g.attestor = attestor

	return nil
}
