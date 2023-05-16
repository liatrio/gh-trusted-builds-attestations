package config

import (
	"flag"
)

type GitHubPullRequestCommandOptions struct {
	GlobalOptions
	fs          *flag.FlagSet
	GithubToken string
}

func NewGitHubPullRequestCommandOptions() *GitHubPullRequestCommandOptions {
	c := &GitHubPullRequestCommandOptions{}

	c.fs = flag.NewFlagSet("github-pull-request", flag.ContinueOnError)
	c.AddFlags(c.fs)

	return c
}

func (c *GitHubPullRequestCommandOptions) Parse(args []string) error {
	githubToken, err := GetGitHubEnvToken()
	if err != nil {
		return err
	}
	c.GithubToken = githubToken

	return c.fs.Parse(args)
}
