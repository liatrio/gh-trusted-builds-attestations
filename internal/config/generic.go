package config

import (
	"flag"
)

type GenericCommandOptions struct {
	GlobalOptions
	fs              *flag.FlagSet
	AttestationPath string
}

func NewGenericCommandOptions() *GenericCommandOptions {
	c := &GenericCommandOptions{}

	c.fs = flag.NewFlagSet("generic", flag.ContinueOnError)
	c.fs.StringVar(&c.AttestationPath, "attestation-path", "", "File path to an intoto attestation")
	c.AddFlags(c.fs)

	return c
}

func (c *GenericCommandOptions) Parse(args []string) error {
	return c.fs.Parse(args)
}
