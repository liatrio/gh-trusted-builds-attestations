package cmd

import (
	"context"

	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/github_pull_request"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
)

type GitHubPullRequest struct {
	ctx      context.Context
	opts     *config.GitHubPullRequestCommandOptions
	attestor *github_pull_request.GitHubPullRequestAttestor
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

	attestor, err := github_pull_request.NewAttestor(ctx, opts)
	if err != nil {
		return err
	}

	g.attestor = attestor

	return nil
}
