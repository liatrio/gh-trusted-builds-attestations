package vsa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-github/v52/github"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/intoto"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"golang.org/x/oauth2"
)

func Attest(opts *config.VsaCommandOptions) error {
	ctx := context.Background()

	attestations, err := collectAttestations(ctx, opts)
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

func collectAttestations(ctx context.Context, opts *config.VsaCommandOptions) ([]oci.Signature, error) {
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

	rekorClient, err := rekor.GetRekorClient(opts.RekorUrl)
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
		Identities: []cosign.Identity{
			{
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "https://github.com/liatrio/gh-trusted-builds-workflows/.github/workflows/build-and-push.yaml@refs/heads/main",
			},
			{
				Issuer:  "https://token.actions.githubusercontent.com",
				Subject: "https://github.com/liatrio/gh-trusted-builds-workflows/.github/workflows/scan-image.yaml@refs/heads/main",
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if !bundleVerified {
		return nil, fmt.Errorf("attestation verification failed")
	}

	return attestations, nil
}

func evaluatePolicy(ctx context.Context, opts *config.VsaCommandOptions, attestations []oci.Signature) (bool, error) {
	err := downloadOPABundle(ctx, opts)
	if err != nil {
		return false, err
	}

	query := "data.governance.allow"
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
		rego.Query(query),
		rego.Input(input),
		rego.EnablePrintStatements(true),
		rego.LoadBundle("bundle.tar.gz"),
	)

	rs, err := r.Eval(context.Background())
	if err != nil {
		return false, err
	}

	return rs.Allowed(), nil
}

func downloadOPABundle(ctx context.Context, opts *config.VsaCommandOptions) error {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: opts.GitHubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	gh := github.NewClient(tc)

	tag, response, err := gh.Repositories.GetReleaseByTag(ctx, "liatrio", "gh-trusted-builds-policy", opts.PolicyVersion)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	var id int64
	for _, asset := range tag.Assets {
		if *asset.Name == "bundle.tar.gz" {
			id = *asset.ID
		}
		break
	}

	rc, _, err := gh.Repositories.DownloadReleaseAsset(ctx, "liatrio", "gh-trusted-builds-policy", id, http.DefaultClient)
	if err != nil {
		return err
	}
	defer rc.Close()

	bundleFile, err := os.Create("bundle.tar.gz")
	if err != nil {
		return err
	}
	defer bundleFile.Close()

	_, err = io.Copy(bundleFile, rc)
	if err != nil {
		return err
	}

	return nil
}
