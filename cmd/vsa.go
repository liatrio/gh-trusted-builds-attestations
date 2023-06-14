package cmd

import (
	"github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/vsa"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/spf13/cobra"
)

func VsaCmd() *cobra.Command {
	opts := config.NewVsaCommandOptions()

	cmd := &cobra.Command{
		Use:   "vsa",
		Short: "Creates a SLSA verification summary attestation by evaluating an artifact against an OPA policy",
		RunE: func(cmd *cobra.Command, args []string) error {
			return vsa.Attest(opts)
		},
	}

	opts.AddFlags(cmd)

	return cmd
}
