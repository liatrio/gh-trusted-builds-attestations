package cmd

import "context"

type Cmd interface {
	Run() error
	Is(string) bool
	Init(ctx context.Context, flags []string) error
}
