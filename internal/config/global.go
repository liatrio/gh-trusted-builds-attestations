package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
)

type GlobalOptions struct {
	OidcIssuerUrl,
	OidcClientId,
	FulcioUrl,
	RekorUrl string
}

func NewGlobalOptions() GlobalOptions {
	return GlobalOptions{
		FulcioUrl: "https://fulcio.sigstore.dev",
		RekorUrl:  "https://rekor.sigstore.dev",
	}
}

func (g *GlobalOptions) AddFlags(fs *flag.FlagSet) {
	fs.Func("rekor-url", "Rekor server URL", func(s string) error {
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return err
		}
		g.RekorUrl = u.String()
		return nil
	})

	fs.Func("fulcio-url", "Fulcio server url", func(s string) error {
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return err
		}
		g.FulcioUrl = u.String()
		return nil
	})

	fs.Func("oidc-issuer-url", "OIDC issuer url for keyless signing", func(s string) error {
		u, err := url.ParseRequestURI(s)
		if err != nil {
			return err
		}
		g.OidcIssuerUrl = u.String()
		return nil
	})

	fs.StringVar(&g.OidcClientId, "oidc-client-id", "sigstore", "OIDC client id for keyless signing")
}

func GetGitHubEnvToken() (string, error) {
	githubToken, githubTokenExists := os.LookupEnv("GITHUB_TOKEN")

	if !githubTokenExists {
		return "", fmt.Errorf("GITHUB_TOKEN not provided")
	}

	return githubToken, nil
}
