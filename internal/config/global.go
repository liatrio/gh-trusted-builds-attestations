package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

var (
	supportedSchemes = regexp.MustCompile("^https?$")
)

type GlobalOptions struct {
	FulcioUrl,
	RekorUrl,
	OidcIssuerUrl *UrlValue

	OidcClientId,
	IdToken,
	ArtifactUri string
	ArtifactDigest *DigestValue
}

type UrlValue struct {
	allowRelative bool
	value         *url.URL
}

func (u *UrlValue) Set(value string) error {
	parseUrl := url.ParseRequestURI
	if u.allowRelative {
		parseUrl = url.Parse
	}

	parsedUrl, err := parseUrl(value)
	if err != nil {
		return err
	}

	if parsedUrl.IsAbs() && !supportedSchemes.MatchString(parsedUrl.Scheme) {
		return fmt.Errorf("unsupported scheme provided, should be one of http, https")
	}

	u.value = parsedUrl

	return nil
}

func (u *UrlValue) String() string {
	if u.value == nil {
		return ""
	}

	return u.value.String()
}

func (u *UrlValue) Type() string {
	return "url"
}

func (u *UrlValue) Value() *url.URL {
	return u.value
}

type DigestValue struct {
	Hex       string
	Algorithm string
}

func (d *DigestValue) Set(digest string) error {
	var found bool
	d.Algorithm, d.Hex, found = strings.Cut(digest, ":")
	if !found {
		return fmt.Errorf("expected artifact digest to be of the form hashType:digestValue")
	}

	return nil
}

func (d *DigestValue) String() string {
	if d.Algorithm == "" && d.Hex == "" {
		return ""
	}

	return d.Algorithm + ":" + d.Hex
}

func (d *DigestValue) Type() string {
	return "digest"
}

func NewGlobalOptions() GlobalOptions {
	fulcioUrl, _ := url.ParseRequestURI("https://fulcio.sigstore.dev")
	rekorUrl, _ := url.ParseRequestURI("https://rekor.sigstore.dev")
	issuerUrl, _ := url.ParseRequestURI("https://oauth2.sigstore.dev/auth")

	return GlobalOptions{
		FulcioUrl:      &UrlValue{value: fulcioUrl},
		RekorUrl:       &UrlValue{value: rekorUrl},
		OidcIssuerUrl:  &UrlValue{value: issuerUrl},
		ArtifactDigest: &DigestValue{},
	}
}

func (g *GlobalOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&g.ArtifactUri, "artifact-uri", "", "URI of the OCI artifact")
	cobra.CheckErr(cmd.MarkFlagRequired("artifact-uri"))

	cmd.Flags().Var(g.ArtifactDigest, "artifact-digest", "Digest of the OCI artifact. Should be prefixed with the digest hash type, e.g., sha256:abc123")
	cobra.CheckErr(cmd.MarkFlagRequired("artifact-digest"))

	cmd.Flags().Var(g.FulcioUrl, "fulcio-url", "Fulcio server URL")
	cmd.Flags().Var(g.RekorUrl, "rekor-url", "Rekor server URL")
	cmd.Flags().Var(g.OidcIssuerUrl, "oidc-issuer-url", "OIDC issuer url for keyless signing")
	cmd.Flags().StringVar(&g.OidcClientId, "oidc-client-id", "sigstore", "OIDC client id for keyless signing")
	cmd.Flags().StringVar(&g.IdToken, "id-token", "", "ID token to use for keyless signing")
}

func (g *GlobalOptions) FullArtifactId() string {
	return fmt.Sprintf("%s@%s", g.ArtifactUri, g.ArtifactDigest.String())
}

func (g *GlobalOptions) KeyOpts() options.KeyOpts {
	return options.KeyOpts{
		IDToken:      g.IdToken,
		OIDCIssuer:   g.OidcIssuerUrl.String(),
		OIDCClientID: g.OidcClientId,
		FulcioURL:    g.FulcioUrl.String(),
		RekorURL:     g.RekorUrl.String(),
	}
}
