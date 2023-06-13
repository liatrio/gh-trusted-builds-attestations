package main

import (
	"context"
	"log"
	"os"

	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("no subcommand given, please run `help` for more information")
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

	log.Fatal("no matching subcommand given, please run `help` for more information")
}
