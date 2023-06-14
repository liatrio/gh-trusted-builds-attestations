package cmd

import (
	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/github_pull_request"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/spf13/cobra"
)

func GitHubPullRequestCmd() *cobra.Command {
	opts := config.NewGitHubPullRequestCommandOptions()

	cmd := &cobra.Command{
		Use:   "github-pull-request",
		Short: "Creates a pull request attestation indicating who reviewed a change",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.GetTokenFromEnv(); err != nil {
				return err
			}

			attestor, err := github_pull_request.NewAttestor(cmd.Context(), opts)
			if err != nil {
				return err
			}

			return attestor.Attest(cmd.Context(), opts)
		},
	}

	opts.AddFlags(cmd)

	return cmd
}
