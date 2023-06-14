package config

import (
	"fmt"
	"os"
)

type GitHubPullRequestCommandOptions struct {
	GlobalOptions
	GitHubToken string
}

func NewGitHubPullRequestCommandOptions() *GitHubPullRequestCommandOptions {
	c := &GitHubPullRequestCommandOptions{
		GlobalOptions: NewGlobalOptions(),
	}

	return c
}

func (g *GitHubPullRequestCommandOptions) GetTokenFromEnv() error {
	githubToken, githubTokenExists := os.LookupEnv("GITHUB_TOKEN")

	if !githubTokenExists {
		return fmt.Errorf("GITHUB_TOKEN not provided")
	}

	g.GitHubToken = githubToken

	return nil
}
