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
	fs             *flag.FlagSet
	ArtifactDigest *Digest
	ArtifactUri,
	CommitSha,
	PolicyVersion,
	VerifierId,
	PredicateFilePath,
	GithubToken string
}

func NewVsaCommandOptions() *VsaCommandOptions {
	c := &VsaCommandOptions{
		ArtifactDigest: &Digest{},
		GlobalOptions:  NewGlobalOptions(),
	}

	c.fs = flag.NewFlagSet("vsa", flag.ContinueOnError)
	c.fs.StringVar(&c.ArtifactDigest.Value, "artifact-digest", "", "Digest of the OCI artifact. Should be prefixed with the digest hash type, e.g., sha256:60bcfdd2...")
	c.fs.StringVar(&c.ArtifactUri, "artifact-uri", "", "URI of the OCI artifact")
	c.fs.StringVar(&c.CommitSha, "commit-sha", "", "Git commit associated with the artifact")
	c.fs.StringVar(&c.PolicyVersion, "policy-version", "", "GitHub release version of OPA bundle")
	c.fs.StringVar(&c.VerifierId, "verifier-id", "", "ID of entity verifying policy for the VSA")
	c.fs.StringVar(&c.PredicateFilePath, "predicate-file-path", "vsa.predicate.json", "The filename to write the VSA predicate")
	c.AddFlags(c.fs)

	return c
}

func (c *VsaCommandOptions) Parse(args []string) error {
	githubToken, err := GetGitHubEnvToken()
	if err != nil {
		return err
	}
	c.GithubToken = githubToken
	if err = c.fs.Parse(args); err != nil {
		return err
	}

	return c.ArtifactDigest.Parse()
}
