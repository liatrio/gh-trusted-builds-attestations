package vsa

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"

	"github.com/google/go-github/v52/github"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/intoto"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sigstore/rekor/pkg/generated/models"
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

	vsaFile, err := os.Create(opts.PredicateFilePath)
	if err != nil {
		return err
	}
	defer vsaFile.Close()

	_, err = io.Copy(vsaFile, bytes.NewReader(vsa))
	if err != nil {
		return err
	}

	return nil
}

func collectAttestations(ctx context.Context, opts *config.VsaCommandOptions) ([]models.LogEntry, error) {
	var uuids []string

	artifactUUIDs, err := sigstore.SearchByHash(ctx, opts.ArtifactDigest.RawDigest, opts.RekorUrl)
	if err != nil {
		return nil, err
	}
	uuids = append(uuids, artifactUUIDs...)

	sourceUUIDs, err := sigstore.SearchByHash(ctx, opts.CommitSha, opts.RekorUrl)
	if err != nil {
		return nil, err
	}
	uuids = append(uuids, sourceUUIDs...)

	entries, err := sigstore.RetrieveEntriesByUUID(ctx, uuids, opts.RekorUrl)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func evaluatePolicy(ctx context.Context, opts *config.VsaCommandOptions, entries []models.LogEntry) (bool, error) {
	err := downloadOPABundle(ctx, opts)
	if err != nil {
		return false, err
	}

	query := "data.governance.allow"
	var input []map[string]string

	for _, entry := range entries {
		for _, e := range entry {

			dec, err := base64.StdEncoding.DecodeString(e.Attestation.Data.String())
			if err != nil {
				return false, err
			}

			input = append(input, map[string]string{
				"Attestation": string(dec),
			})
		}
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
		&oauth2.Token{AccessToken: opts.GithubToken},
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
