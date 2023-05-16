package attestors

import (
	"context"
	"errors"
	"fmt"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"log"
	"os"

	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

const (
	GenericAttestorName = "generic"
)

var (
	ErrAttestationPath = errors.New("must provide a file path to an attestation")
)

type GenericAttestor struct {
	signer sigstore.Signer
}

func NewGenericAttestor(opts *config.GenericCommandOptions) (*GenericAttestor, error) {
	signer, err := sigstore.NewSigner(opts.RekorUrl)
	if err != nil {
		return nil, err
	}

	return &GenericAttestor{signer: signer}, nil
}

func (g *GenericAttestor) Attest(ctx context.Context, opts *config.GenericCommandOptions) error {
	if opts.AttestationPath == "" {
		return ErrAttestationPath
	}

	payload, err := os.ReadFile(opts.AttestationPath)
	if err != nil {
		return fmt.Errorf("error reading attestation json: %v", err)
	}

	logEntry, err := g.signer.SignInTotoAttestation(ctx, payload, options.KeyOpts{
		KeyRef:           opts.KmsKeyUri,
		FulcioURL:        opts.FulcioUrl,
		RekorURL:         opts.RekorUrl,
		SkipConfirmation: true,
	})

	if err != nil {
		return err
	}

	log.Printf("Uploaded attestation with log index #%d\n", *logEntry.LogIndex)

	return nil
}

func (g *GenericAttestor) Name() string {
	return GenericAttestorName
}
