package main

import (
	"context"
	"fmt"
	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal(fmt.Errorf("no attestation type given"))
	}

	ctx := context.Background()
	subCommand := os.Args[1]
	flags := os.Args[2:]

	commands := []cmd.Cmd{
		&cmd.GitHubPullRequest{},
		&cmd.VSA{},
		&cmd.Version{},
		&cmd.Help{},
	}

	for _, c := range commands {
		if c.Is(subCommand) {
			err := c.Init(ctx, flags)
			if err != nil {
				log.Fatal(err)
			}

			err = c.Run()
			if err != nil {
				log.Fatal(err)
			}

			os.Exit(0)
		}
	}

	log.Fatal(fmt.Errorf("no matching command given, please run `help` for more information"))
}
