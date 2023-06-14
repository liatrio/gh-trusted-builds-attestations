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
	"github.com/liatrio/gh-trusted-builds-attestations/internal/intoto"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

func Attest(opts *config.VsaCommandOptions) error {
	ctx := context.Background()

	if opts.PolicyUrl.Value().IsAbs() {
		if err := downloadOPABundle(ctx, opts, policyBundleFilePath(opts.PolicyUrl.Value())); err != nil {
			return err
		}
	}

	identities, err := querySignerIdentitiesFromPolicy(ctx, opts)
	if err != nil {
		return err
	}

	attestations, err := collectAttestations(ctx, opts, identities)
	if err != nil {
		return err
	}

	allowed, err := evaluatePolicy(ctx, opts, attestations)
	if err != nil {
		return err
	}

	vsa, err := intoto.CreateVerificationSummaryAttestation(opts, allowed, attestations)
	if err != nil {
		return err
	}

	signer, err := sigstore.NewSigner(opts.RekorUrl.String())
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

func collectAttestations(ctx context.Context, opts *config.VsaCommandOptions, identities []cosign.Identity) ([]oci.Signature, error) {
	imageRef, err := name.ParseReference(opts.FullArtifactId())
	if err != nil {
		return nil, fmt.Errorf("error parsing image uri: %w", err)
	}

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

	rekorClient, err := rekor.GetRekorClient(opts.RekorUrl.String())
	if err != nil {
		return nil, err
	}

	attestations, bundleVerified, err := cosign.VerifyImageAttestations(ctx, imageRef, &cosign.CheckOpts{
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier,
		RekorClient:       rekorClient,
		RekorPubKeys:      rekorKeys,
		RootCerts:         fulcioRoots,
		IntermediateCerts: fulcioIntermediates,
		CTLogPubKeys:      ctLogKeys,
		Identities:        identities,
	})
	if err != nil {
		return nil, err
	}

	if !bundleVerified {
		return nil, fmt.Errorf("attestation verification failed")
	}

	return attestations, nil
}

func querySignerIdentitiesFromPolicy(ctx context.Context, opts *config.VsaCommandOptions) ([]cosign.Identity, error) {
	r := rego.New(
		rego.Query(opts.SignerIdentitiesQuery),
		rego.EnablePrintStatements(opts.Debug),
		rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		rego.LoadBundle(policyBundleFilePath(opts.PolicyUrl.Value())),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}

	if len(rs) < 1 {
		return nil, errors.New("missing signer identities")
	}

	identitiesJson, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}

	var identities []cosign.Identity
	if err = json.Unmarshal(identitiesJson, &identities); err != nil {
		return nil, err
	}

	return identities, nil
}

func evaluatePolicy(ctx context.Context, opts *config.VsaCommandOptions, attestations []oci.Signature) (bool, error) {
	var input []map[string]string

	for _, attestation := range attestations {
		payload, err := attestation.Payload()
		if err != nil {
			return false, err
		}
		var intotoWrapper map[string]any
		if err = json.Unmarshal(payload, &intotoWrapper); err != nil {
			return false, err
		}
		att, ok := intotoWrapper["payload"]
		if !ok {
			return false, fmt.Errorf("unexpected format")
		}

		dec, err := base64.StdEncoding.DecodeString(att.(string))
		if err != nil {
			return false, err
		}

		input = append(input, map[string]string{
			"Attestation": string(dec),
		})
	}

	r := rego.New(
		rego.Query(opts.PolicyQuery),
		rego.Input(input),
		rego.EnablePrintStatements(opts.Debug),
		rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		rego.LoadBundle(policyBundleFilePath(opts.PolicyUrl.Value())),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return false, err
	}

	return rs.Allowed(), nil
}

func downloadOPABundle(ctx context.Context, opts *config.VsaCommandOptions, outputFilepath string) error {
	client := http.Client{Timeout: time.Minute}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.PolicyUrl.String(), nil)
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

func policyBundleFilePath(policyUrl *url.URL) string {
	if policyUrl.IsAbs() {
		return "bundle.tar.gz"
	}

	return policyUrl.String()
}
