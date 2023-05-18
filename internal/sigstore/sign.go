package sigstore

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/types"
	rekor "github.com/sigstore/rekor/pkg/client"
	rekorgen "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"

	// load OIDC providers
	_ "github.com/sigstore/cosign/v2/pkg/providers/all"
)

var (
	buildInfo, _ = debug.ReadBuildInfo()
	userAgent    = fmt.Sprintf("ag-custom-attestor/%s (%s;%s)", buildInfo.Main.Version, runtime.GOOS, runtime.GOARCH)
)

type Signer interface {
	SignInTotoAttestation(ctx context.Context, payload []byte, opts options.KeyOpts) (*models.LogEntryAnon, error)
}

type cosignSigner struct {
	rekor *rekorgen.Rekor
}

func NewSigner(rekorUrl string) (Signer, error) {
	rekorClient, err := rekor.GetRekorClient(rekorUrl, rekor.WithUserAgent(userAgent))
	if err != nil {
		return nil, fmt.Errorf("error instantiating Rekor client: %v", err)
	}

	return &cosignSigner{rekor: rekorClient}, nil
}

func (s *cosignSigner) SignInTotoAttestation(ctx context.Context, payload []byte, opts options.KeyOpts) (*models.LogEntryAnon, error) {
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", opts)
	if err != nil {
		return nil, fmt.Errorf("error creating signer: %v", err)
	}
	defer sv.Close()

	publicKeyPem, err := sv.Bytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting public key bytes: %v", err)
	}

	wrapped := dsse.WrapSigner(sv, types.IntotoPayloadType)
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("error signing attestation: %s", err)
	}

	logEntry, err := cosign.TLogUploadInTotoAttestation(ctx, s.rekor, signedPayload, publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("error uploading to tlog: %v", err)
	}

	return logEntry, nil
}
