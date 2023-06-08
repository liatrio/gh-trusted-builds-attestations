package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

type GlobalOptions struct {
	OidcIssuerUrl,
	OidcClientId,
	FulcioUrl,
	RekorUrl,
	IdToken,
	ArtifactUri string
	ArtifactDigest *Digest
}

func NewGlobalOptions() GlobalOptions {
	return GlobalOptions{
		FulcioUrl:      "https://fulcio.sigstore.dev",
		RekorUrl:       "https://rekor.sigstore.dev",
		OidcIssuerUrl:  "https://oauth2.sigstore.dev/auth",
		ArtifactDigest: &Digest{},
	}
}

func (g *GlobalOptions) Parse() error {
	return g.ArtifactDigest.Parse()
}

func (g *GlobalOptions) FullArtifactId() string {
	return fmt.Sprintf("%s@%s", g.ArtifactUri, g.ArtifactDigest.Value)
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
	fs.StringVar(&g.ArtifactDigest.Value, "artifact-digest", "", "Digest of the OCI artifact. Should be prefixed with the digest hash type, e.g., sha256:60bcfdd2...")
	fs.StringVar(&g.ArtifactUri, "artifact-uri", "", "URI of the OCI artifact")
	fs.StringVar(&g.IdToken, "id-token", "", "OIDC id token from issuer")
}

func (g *GlobalOptions) KeyOpts() options.KeyOpts {
	return options.KeyOpts{
		IDToken:      g.IdToken,
		OIDCIssuer:   g.OidcIssuerUrl,
		OIDCClientID: g.OidcClientId,
		FulcioURL:    g.FulcioUrl,
		RekorURL:     g.RekorUrl,
	}
}

func GetGitHubEnvToken() (string, error) {
	githubToken, githubTokenExists := os.LookupEnv("GITHUB_TOKEN")

	if !githubTokenExists {
		return "", fmt.Errorf("GITHUB_TOKEN not provided")
	}

	return githubToken, nil
}
