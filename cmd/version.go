package cmd

import (
	"context"
	"github.com/liatrio/gh-trusted-builds-attestations/build"
)

type Version struct {
}

func (v *Version) Init(ctx context.Context, flags []string) error {
	return nil
}

func (v *Version) Is(s string) bool {
	return "version" == s
}

func (v *Version) Run() error {
	println(build.Version)
	return nil
}
