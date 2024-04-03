package config

import (
	"github.com/spf13/cobra"
	"os"
)

type VsaCommandOptions struct {
	GlobalOptions
	PolicyUrl             *UrlValue
	VerifierId            string
	Debug                 bool
	SignerIdentitiesQuery string
	PolicyQuery           string
	GitHubToken           string
}

func NewVsaCommandOptions() *VsaCommandOptions {
	return &VsaCommandOptions{
		GlobalOptions: NewGlobalOptions(),
		PolicyUrl:     &UrlValue{allowRelative: true},
	}
}

func (vsa *VsaCommandOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&vsa.VerifierId, "verifier-id", "", "ID of entity verifying policy for the VSA")
	cobra.CheckErr(cmd.MarkFlagRequired("verifier-id"))

	cmd.Flags().Var(vsa.PolicyUrl, "policy-url", "Location of policy bundle that will be used to determine VSA result")
	cobra.CheckErr(cmd.MarkFlagRequired("policy-url"))

	cmd.Flags().StringVar(&vsa.SignerIdentitiesQuery, "signer-identities-query", "data.governance.signer_identities", "Rego query to retrieve keyless signer identities")
	cmd.Flags().StringVar(&vsa.PolicyQuery, "policy-query", "data.governance.allow", "Rego query to evaluate attestations against policy")
	cmd.Flags().BoolVar(&vsa.Debug, "debug", false, "Emit debug logs from policy evaluation")

	vsa.GlobalOptions.AddFlags(cmd)
}

func (vsa *VsaCommandOptions) GetTokenFromEnv() {
	vsa.GitHubToken = os.Getenv("GITHUB_TOKEN")
}
