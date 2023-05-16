package config

import (
	"flag"
	"fmt"
	"net/url"
	"os"
)

type GlobalOptions struct {
	FulcioUrl,
	RekorUrl,
	KmsKeyUri string
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

	fs.StringVar(&g.KmsKeyUri, "kms-key-uri", "", "KMS Key Id for signing")
}

func GetGitHubEnvToken() (string, error) {
	githubToken, githubTokenExists := os.LookupEnv("GITHUB_TOKEN")

	if !githubTokenExists {
		return "", fmt.Errorf("GITHUB_TOKEN not provided")
	}

	return githubToken, nil
}
