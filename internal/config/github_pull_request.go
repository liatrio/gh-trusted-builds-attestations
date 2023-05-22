package config

import (
	"flag"
)

type GitHubPullRequestCommandOptions struct {
	GlobalOptions
	fs          *flag.FlagSet
	GitHubToken string
}

func NewGitHubPullRequestCommandOptions() *GitHubPullRequestCommandOptions {
	c := &GitHubPullRequestCommandOptions{
		GlobalOptions: NewGlobalOptions(),
	}

	c.fs = flag.NewFlagSet("github-pull-request", flag.ContinueOnError)
	c.AddFlags(c.fs)

	return c
}

func (c *GitHubPullRequestCommandOptions) Parse(args []string) error {
	githubToken, err := GetGitHubEnvToken()
	if err != nil {
		return err
	}
	c.GitHubToken = githubToken
	err = c.fs.Parse(args)
	if err != nil {
		return err
	}

	return c.GlobalOptions.ArtifactDigest.Parse()
}
