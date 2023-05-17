package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/vsa"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal(fmt.Errorf("no attestation type given"))
	}

	var err error
	ctx := context.Background()
	subCommand := os.Args[1]
	flags := os.Args[2:]

	switch subCommand {
	case "vsa":
		opts := config.NewVsaCommandOptions()
		if err = opts.Parse(flags); err != nil {
			break
		}
		err = vsa.Attest(opts)
	case "github-pull-request":
		opts := config.NewGitHubPullRequestCommandOptions()
		if err = opts.Parse(flags); err != nil {
			break
		}
		attestor, err := attestors.NewGitHubPullRequestAttestor(ctx, opts)
		if err != nil {
			break
		}
		err = attestor.Attest(ctx, opts)
	default:
		log.Fatal(fmt.Errorf("attestation type not recognized"))
	}

	if err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
