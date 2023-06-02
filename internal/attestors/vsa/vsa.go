package vsa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

func Attest(opts *config.VsaCommandOptions) error {
	ctx := context.Background()

	result, err := evaluatePolicy(ctx, opts)
	if err != nil {
		return err
	}

	vsa, err := createVerificationSummaryAttestation(opts, result)
	if err != nil {
		return err
	}

	signer, err := sigstore.NewSigner(opts.RekorUrl)
	if err != nil {
		return err
	}

	logEntry, err := signer.SignInTotoAttestation(ctx, vsa, opts.KeyOpts(), opts.FullArtifactId())
	if err != nil {
		return err
	}
	log.Printf("Uploaded attestation with log index: %d\n", *logEntry.LogIndex)

	return nil
}

func evaluatePolicy(ctx context.Context, opts *config.VsaCommandOptions) (*policyEvaluationResult, error) {
	var bundleFilepath string

	if opts.PolicyUrl.IsAbs() {
		bundleFilepath = "bundle.tar.gz"

		err := downloadOPABundle(ctx, opts.PolicyUrl, bundleFilepath)
		if err != nil {
			return nil, err
		}
	} else {
		bundleFilepath = opts.PolicyUrl.Path
	}

	query := "data.governance.result"

	r := rego.New(
		rego.Query(query),
		rego.Input(map[string]string{"image": opts.FullArtifactId()}),
		rego.Function2(
			&rego.Function{
				Name:             "verify_image_attestations",
				Decl:             types.NewFunction(types.Args(types.S, types.A), types.A),
				Memoize:          true,
				Nondeterministic: true,
			},
			opaVerifyImageAttestations(ctx, opts),
		),
		rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		rego.EnablePrintStatements(true),
		rego.LoadBundle(bundleFilepath),
	)

	rs, err := r.Eval(context.Background())
	if err != nil {
		return nil, err
	}

	if len(rs) < 1 {
		return nil, errors.New("no result from policy")
	}

	resultBytes, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var result policyEvaluationResult
	if err = json.Unmarshal(resultBytes, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func opaVerifyImageAttestations(ctx context.Context, opts *config.VsaCommandOptions) func(_ rego.BuiltinContext, imageArg, identitiesArg *ast.Term) (*ast.Term, error) {
	return func(_ rego.BuiltinContext, imageArg, identitiesArg *ast.Term) (*ast.Term, error) {
		var image string
		if err := ast.As(imageArg.Value, &image); err != nil {
			return nil, err
		}

		var identities []cosign.Identity
		if err := ast.As(identitiesArg.Value, &identities); err != nil {
			return nil, err
		}

		checkOpts, err := makeCosignCheckOpts(ctx, opts, identities)
		if err != nil {
			return nil, err
		}

		imageRef, err := name.ParseReference(image)
		sigs, bundleVerified, err := cosign.VerifyImageAttestations(ctx, imageRef, checkOpts)
		if err != nil {
			return nil, err
		}

		if !bundleVerified {
			return nil, fmt.Errorf("attestation bundle failed verification")
		}

		var attestations []*attestationMetadata
		for _, attestation := range sigs {
			payload, err := attestation.Payload()
			if err != nil {
				return nil, err
			}

			var intotoWrapper map[string]any
			if err = json.Unmarshal(payload, &intotoWrapper); err != nil {
				return nil, err
			}

			att, ok := intotoWrapper["payload"]
			if !ok {
				return nil, fmt.Errorf("unexpected attestation format")
			}

			decoded, err := base64.StdEncoding.DecodeString(att.(string))
			if err != nil {
				return nil, err
			}

			digest, err := attestation.Digest()
			if err != nil {
				return nil, err
			}

			bundle, err := attestation.Bundle()
			if err != nil {
				return nil, err
			}

			attestations = append(attestations, &attestationMetadata{
				Attestation:     string(decoded),
				RekorLogIndex:   bundle.Payload.LogIndex,
				DigestAlgorithm: digest.Algorithm,
				DigestHex:       digest.Hex,
			})
		}

		value, err := ast.InterfaceToValue(attestations)
		if err != nil {
			return nil, err
		}
		return ast.NewTerm(value), nil
	}
}

func downloadOPABundle(ctx context.Context, bundleUrl *url.URL, outputFilepath string) error {
	client := http.Client{Timeout: time.Minute}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleUrl.String(), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bundleFile, err := os.Create(outputFilepath)
	if err != nil {
		return err
	}
	defer bundleFile.Close()

	_, err = io.Copy(bundleFile, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func makeCosignCheckOpts(ctx context.Context, opts *config.VsaCommandOptions, identities []cosign.Identity) (*cosign.CheckOpts, error) {
	fulcioRoots, err := fulcioroots.Get()
	if err != nil {
		return nil, err
	}
	fulcioIntermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, err
	}

	ctLogKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, err
	}

	rekorKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.GetRekorClient(opts.RekorUrl)
	if err != nil {
		return nil, err
	}

	return &cosign.CheckOpts{
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier,
		RekorClient:       rekorClient,
		RekorPubKeys:      rekorKeys,
		RootCerts:         fulcioRoots,
		IntermediateCerts: fulcioIntermediates,
		CTLogPubKeys:      ctLogKeys,
		Identities:        identities,
	}, nil
}
