package vsa

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	gh "github.com/liatrio/gh-trusted-builds-attestations/internal/github"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

var (
	matchTreeUrl = regexp.MustCompile(`https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/tree/(?P<branchOrCommit>[^/]+)/(?P<path>[^?]+)`)
)

func Attest(opts *config.VsaCommandOptions) error {
	ctx := context.Background()
	var err error
	bundlePath := opts.PolicyUrl.String()

	if opts.PolicyUrl.Value().IsAbs() {
		if bundlePath, err = downloadOPABundle(ctx, opts); err != nil {
			return err
		}
	}

	identities, err := querySignerIdentitiesFromPolicy(ctx, opts, bundlePath)
	if err != nil {
		return err
	}

	attestations, err := collectAttestations(ctx, opts, identities)
	if err != nil {
		return err
	}

	allowed, err := evaluatePolicy(ctx, opts, bundlePath, attestations)
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

func querySignerIdentitiesFromPolicy(ctx context.Context, opts *config.VsaCommandOptions, bundlePath string) ([]cosign.Identity, error) {
	r := rego.New(
		rego.Query(opts.SignerIdentitiesQuery),
		rego.EnablePrintStatements(opts.Debug),
		rego.PrintHook(topdown.NewPrintHook(os.Stderr)),
		rego.LoadBundle(bundlePath),
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

func evaluatePolicy(ctx context.Context, opts *config.VsaCommandOptions, bundlePath string, attestations []oci.Signature) (bool, error) {
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
		rego.LoadBundle(bundlePath),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return false, err
	}

	return rs.Allowed(), nil
}

func downloadOPABundle(ctx context.Context, opts *config.VsaCommandOptions) (string, error) {
	if matchTreeUrl.MatchString(opts.PolicyUrl.String()) {
		return downloadGitHubArchive(ctx, opts)
	}

	return downloadBundleArchive(ctx, opts)
}

func downloadBundleArchive(ctx context.Context, opts *config.VsaCommandOptions) (string, error) {
	outputFilePath := "bundle.tar.gz"
	client := http.Client{Timeout: time.Minute}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.PolicyUrl.String(), nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bundleFile, err := os.Create(outputFilePath)
	if err != nil {
		return "", err
	}
	defer bundleFile.Close()

	_, err = io.Copy(bundleFile, resp.Body)
	if err != nil {
		return "", err
	}

	return outputFilePath, nil
}

func downloadGitHubArchive(ctx context.Context, opts *config.VsaCommandOptions) (string, error) {
	matches := matchTreeUrl.FindStringSubmatch(opts.PolicyUrl.String())
	if len(matches) == 0 {
		return "", fmt.Errorf("unexpected url format")
	}

	owner := matches[matchTreeUrl.SubexpIndex("owner")]
	repo := matches[matchTreeUrl.SubexpIndex("repo")]
	branchOrCommit := matches[matchTreeUrl.SubexpIndex("branchOrCommit")]
	path := matches[matchTreeUrl.SubexpIndex("path")]

	githubClient, err := gh.New(ctx, opts.GitHubToken)
	if err != nil {
		return "", err
	}

	archive, err := githubClient.GetRepositoryArchiveAtRef(ctx, &gh.RepositorySlug{Owner: owner, Repo: repo}, branchOrCommit)
	if err != nil {
		return "", err
	}

	tmpDir, err := writeArchiveToTmpDir("vsa-policy-*", archive)
	if err != nil {
		return "", err
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", err
	}

	// the archive contains a single directory named in the pattern 'org-repo-commitShortSha'
	// it's difficult to know this upfront because the user can provide a branch name as well as a commit
	dirName := ""
	for _, e := range entries {
		if e.IsDir() && strings.Contains(e.Name(), repo) {
			dirName = e.Name()
		}
	}

	return filepath.Join(tmpDir, dirName, path), nil
}

func writeArchiveToTmpDir(tmpDirPrefix string, archive []byte) (string, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), tmpDirPrefix)
	if err != nil {
		return "", err
	}

	gr, err := gzip.NewReader(bytes.NewReader(archive))
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if err != nil {
			break
		}

		tmpPath := filepath.Join(tmpDir, header.Name)

		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(tmpPath, os.FileMode(header.Mode)); err != nil {
				return "", err
			}
		} else {
			file, err := os.Create(tmpPath)
			if err != nil {
				return "", err
			}

			if _, err := io.Copy(file, tr); err != nil {
				_ = file.Close()
				return "", err
			}

			_ = file.Close()
		}
	}

	return tmpDir, nil
}
