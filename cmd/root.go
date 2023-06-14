package cmd

import (
	"github.com/liatrio/gh-trusted-builds-attestations/build"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "attestation",
		Version: build.Version,
		Short:   "A tool for creating in-toto attestations",
	}
	rootCmd.SetVersionTemplate("{{.Version}}")

	rootCmd.AddCommand(
		GitHubPullRequestCmd(),
		VsaCmd(),
		VersionCmd(),
	)

	return rootCmd
}
