package config

import (
	"flag"
	"fmt"
	"strings"
)

type Digest struct {
	Value     string
	RawDigest string
	Type      string
}

func (d *Digest) Parse() error {
	var found bool
	d.Type, d.RawDigest, found = strings.Cut(d.Value, ":")
	if !found {
		return fmt.Errorf("expected artifact digest to be of the form hashType:digestValue")
	}

	return nil
}

type VsaCommandOptions struct {
	GlobalOptions
	fs *flag.FlagSet
	PolicyVersion,
	VerifierId,
	GitHubToken string
}

func NewVsaCommandOptions() *VsaCommandOptions {
	c := &VsaCommandOptions{
		GlobalOptions: NewGlobalOptions(),
	}

	c.fs = flag.NewFlagSet("vsa", flag.ContinueOnError)
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
	c.GitHubToken = githubToken
	if err = c.fs.Parse(args); err != nil {
		return err
	}

	return c.ArtifactDigest.Parse()
}
