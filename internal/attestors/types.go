package attestors

import (
	"context"
	"errors"
	"net/url"
)

var (
	ErrInvalidRekorUrl  = errors.New("invalid Rekor server URL")
	ErrInvalidFulcioUrl = errors.New("invalid Fulcio server URL")
	ErrInvalidKmsKeyUri = errors.New("invalid KMS key uri")
)

type Config struct {
	AttestationPath string
	FulcioUrl       string
	RekorUrl        string
	KmsKeyUri       string
}

type Attestor interface {
	Attest(context.Context, *Config) error
	Name() string
}

func (c *Config) Validate() error {
	if _, err := url.ParseRequestURI(c.RekorUrl); err != nil {
		return ErrInvalidRekorUrl
	}

	fulcioUrlSet := c.FulcioUrl != ""
	if fulcioUrlSet {
		if _, err := url.ParseRequestURI(c.FulcioUrl); err != nil {
			return ErrInvalidFulcioUrl
		}
	}

	// Require a KMS key if Fulcio URL isn't provided
	if !fulcioUrlSet {
		if _, err := url.ParseRequestURI(c.KmsKeyUri); err != nil {
			return ErrInvalidKmsKeyUri
		}
	}

	return nil
}
