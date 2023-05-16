package config

import (
	"flag"
)

type VsaCommandOptions struct {
	GlobalOptions
	fs *flag.FlagSet
	ArtifactDigest,
	ArtifactUri,
	CommitSha,
	PolicyVersion,
	VerifierId,
	GithubToken string
}

func NewVsaCommandOptions() *VsaCommandOptions {
	c := &VsaCommandOptions{}

	c.fs = flag.NewFlagSet("vsa", flag.ContinueOnError)
	c.fs.StringVar(&c.ArtifactDigest, "artifact-digest", "", "Digest of the OCI artifact")
	c.fs.StringVar(&c.ArtifactUri, "artifact-uri", "", "URI of the OCI artifact")
	c.fs.StringVar(&c.CommitSha, "commit-sha", "", "Git commit associated with the artifact")
	c.fs.StringVar(&c.PolicyVersion, "policy-version", "", "GitHub release version of OPA bundle")
	c.fs.StringVar(&c.VerifierId, "verifier-id", "", "ID of entity verifying policy for the VSA")
	c.AddFlags(c.fs)

	return c
}

func (c *VsaCommandOptions) Parse(args []string) error {
	githubToken, err := GetGitHubEnvToken()
	if err != nil {
		return err
	}
	c.GithubToken = githubToken

	return c.fs.Parse(args)
}
