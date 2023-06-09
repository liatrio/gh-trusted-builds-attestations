package cmd

import (
	"context"
	"fmt"

	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/vsa"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
)

type VSA struct {
	ctx  context.Context
	opts *config.VsaCommandOptions
}

func (v *VSA) Init(ctx context.Context, flags []string) error {
	v.ctx = ctx

	fmt.Println("flags")
	for _, f := range flags {
		fmt.Println(f)
	}

	opts := config.NewVsaCommandOptions()
	err := opts.Parse(flags)
	if err != nil {
		return err
	}
	v.opts = opts

	return nil
}

func (v *VSA) Is(s string) bool {
	return "vsa" == s
}

func (v *VSA) Run() error {
	return vsa.Attest(v.opts)
}
