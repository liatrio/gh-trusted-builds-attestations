package cmd

import "context"

type Help struct {
}

func (h Help) Run() error {
	println(`Commands:

  github-pull-request
  vsa
  version
  help`)
	return nil
}

func (h Help) Is(s string) bool {
	return "help" == s
}

func (h Help) Init(ctx context.Context, flags []string) error {
	return nil
}
