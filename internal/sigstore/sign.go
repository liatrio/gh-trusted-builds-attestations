package sigstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/static"

	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
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
	SignInTotoAttestation(context.Context, []byte, options.KeyOpts, string) (*models.LogEntryAnon, error)
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

func (s *cosignSigner) SignInTotoAttestation(ctx context.Context, payload []byte, keyOpts options.KeyOpts, imageRef string) (*models.LogEntryAnon, error) {
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", keyOpts)
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

	regOpts := options.RegistryOptions{
		AllowInsecure:      false,
		AllowHTTPRegistry:  false,
		KubernetesKeychain: false,
		RefOpts:            options.ReferenceOptions{},
		Keychain:           nil,
	}
	clientOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return logEntry, err
	}
	err = AttachAttestation(logEntry, clientOpts, signedPayload, imageRef, regOpts.NameOptions(), sv)
	if err != nil {
		return logEntry, err
	}

	return logEntry, nil
}

func AttachAttestation(logEntry *models.LogEntryAnon, remoteOpts []ociremote.Option, signedPayload []byte, imageRef string, nameOpts []name.Option, sv *sign.SignerVerifier) error {
	env := ssldsse.Envelope{}
	decoder := json.NewDecoder(bytes.NewReader(signedPayload))
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}

		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}

		if env.PayloadType != types.IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		if len(env.Signatures) == 0 {
			return fmt.Errorf("could not attach attestation without having signatures")
		}

		ref, err := name.ParseReference(imageRef, nameOpts...)
		if err != nil {
			return err
		}
		digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
		if err != nil {
			return err
		}
		// Overwrite "ref" with a digest to avoid a race where we use a tag
		// multiple times, and it potentially points to different things at
		// each access.
		ref = digest

		opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
		if sv.Cert != nil {
			opts = append(opts, static.WithCertChain(sv.Cert, sv.Chain))
		}

		opts = append(opts, static.WithBundle(cbundle.EntryToBundle(logEntry)))
		att, err := static.NewAttestation(payload, opts...)
		if err != nil {
			return err
		}

		se, err := ociremote.SignedEntity(digest, remoteOpts...)
		if err != nil {
			return err
		}

		newSE, err := mutate.AttachAttestationToEntity(se, att)
		if err != nil {
			return err
		}

		// Publish the signatures associated with this entity
		err = ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...)
		if err != nil {
			return err
		}
	}
	return nil
}
