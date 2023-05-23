package config

import (
	"flag"
	"fmt"
	"net/url"
	"regexp"
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
	fs         *flag.FlagSet
	PolicyUrl  *url.URL
	VerifierId string
}

func NewVsaCommandOptions() *VsaCommandOptions {
	c := &VsaCommandOptions{
		GlobalOptions: NewGlobalOptions(),
	}

	c.fs = flag.NewFlagSet("vsa", flag.ContinueOnError)
	c.fs.Func("policy-url", "Location of policy bundle that will be used to determine VSA result", func(s string) error {
		u, err := url.Parse(s)
		if err != nil {
			return err
		}

		supportedSchemes := regexp.MustCompile("^https?$")
		if u.IsAbs() && !supportedSchemes.MatchString(u.Scheme) {
			return fmt.Errorf("unsupported scheme provided, should be one of http, https")
		}

		c.PolicyUrl = u
		return nil
	})

	c.fs.StringVar(&c.VerifierId, "verifier-id", "", "ID of entity verifying policy for the VSA")
	c.AddFlags(c.fs)

	return c
}

func (c *VsaCommandOptions) Parse(args []string) error {
	if err := c.fs.Parse(args); err != nil {
		return err
	}

	if c.PolicyUrl == nil {
		return fmt.Errorf("policy-url must be provided")
	}

	return c.ArtifactDigest.Parse()
}
