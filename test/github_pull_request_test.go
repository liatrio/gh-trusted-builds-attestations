package test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	pull_request_v1 "github.com/liatrio/gh-trusted-builds-attestations/internal/attestations/github/pull_request/v1"
	ghpratt "github.com/liatrio/gh-trusted-builds-attestations/internal/attestors/github_pull_request"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/github"
	assert "github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"gopkg.in/dnaeon/go-vcr.v3/cassette"
	"gopkg.in/dnaeon/go-vcr.v3/recorder"
)

const (
	githubPrFixtureRepository = "https://github.com/liatrio/pr-attestation-fixtures"
	prAttestationType         = "https://liatr.io/attestations/github-pull-request/v1"

	// https://github.com/liatrio/pr-attestation-fixtures/commit/b61029fc9191455fcc833a319d3fd6d0cb0c2c5b
	commitWithNoAssociatedPullRequest = "b61029fc9191455fcc833a319d3fd6d0cb0c2c5b"

	// https://github.com/liatrio/pr-attestation-fixtures/pull/1
	commitWithNoReviews = "d73bb613511d238bf2e379a9f10dd1ffdf1a8a21"

	// https://github.com/liatrio/pr-attestation-fixtures/pull/5
	commitWithApproval = "04a2451c14b44988942695f0407fbe82eeaf802a"

	// https://github.com/liatrio/pr-attestation-fixtures/pull/4
	commitWithChangesRequested = "837b35d04c7bb8ce49f289e1c19effd17e51a812"

	// https://github.com/liatrio/pr-attestation-fixtures/pull/2
	commitWithMultipleReviewsApprovalEndState = "88e6e324fd76aafcf624a862a2c8f8b4595cf1ad"

	// https://github.com/liatrio/pr-attestation-fixtures/pull/6
	commitWithApprovalMultipleReviewsChangesRequestedEndState = "b178ace6bbd65197ea3ceaf425e14b46f7f50c92"
)

func TestGitHubPullRequestAttestation(t *testing.T) {
	t.Parallel()

	type prAttestation struct {
		PredicateType string
		Subject       []in_toto.Subject
		Predicate     *pull_request_v1.Predicate
	}

	newGitHubRecorder := func(t *testing.T) *recorder.Recorder {
		t.Helper()

		oauth2Transport := &oauth2.Transport{
			Source: oauth2.StaticTokenSource(
				&oauth2.Token{AccessToken: githubToken},
			),
		}

		r, err := recorder.NewWithOptions(&recorder.Options{
			CassetteName: filepath.Join("fixtures", "github", t.Name()),
			Mode:         recorder.ModeRecordOnce,
			//Mode:          recorder.ModeRecordOnly,
			RealTransport: oauth2Transport,
		})
		assert.NoError(t, err, "error creating HTTP recorder")

		// oauth2.Transport mutates the request after go-vcr saves it, so the Authorization header should never be persisted.
		// However, this is a safeguard in case that implementation changes.
		r.AddHook(func(interaction *cassette.Interaction) error {
			delete(interaction.Request.Headers, "Authorization")

			return nil
		}, recorder.AfterCaptureHook)

		return r
	}

	stopRecorder := func(t *testing.T, r *recorder.Recorder) {
		t.Helper()

		if err := r.Stop(); err != nil {
			t.Log("error stopping recorder:", err)
		}
	}

	createGitRepoAtHead := func(t *testing.T, commit string, remotes ...string) *git.Repository {
		t.Helper()

		cfg := gitconfig.NewConfig()
		if len(remotes) == 0 {
			remotes = append(remotes, githubPrFixtureRepository)
		}

		cfg.Remotes[git.DefaultRemoteName] = &gitconfig.RemoteConfig{
			Name: git.DefaultRemoteName,
			URLs: remotes,
		}

		store := memory.NewStorage()
		err := store.SetConfig(cfg)
		assert.NoError(t, err, "error configuring in-memory repository")

		headRef := plumbing.NewReferenceFromStrings(plumbing.HEAD.String(), commit)
		err = store.SetReference(headRef)
		assert.NoError(t, err, "error setting reference on in-memory repository")

		return &git.Repository{
			Storer: store,
		}
	}

	makeCtx := func(r *recorder.Recorder, repo *git.Repository) context.Context {
		ctx := context.WithValue(context.Background(), github.GitHubHttpClientCtxKey, r.GetDefaultClient())

		return context.WithValue(ctx, ghpratt.GitRepositoryOverrideCtxKey, repo)
	}

	parseTime := func(t *testing.T, timestamp string) time.Time {
		t.Helper()

		parsed, err := time.Parse(time.RFC3339, timestamp)
		assert.NoError(t, err)

		return parsed
	}

	runAttestationCmd := func(t *testing.T, ctx context.Context, artifact *containerImage) {
		t.Helper()

		ghprCmd := cmd.GitHubPullRequest{}
		flags := makeGlobalFlags(artifact.digest.String())
		err := ghprCmd.Init(ctx, flags)
		assert.NoError(t, err, "failure initializing test command")
		assert.NoError(t, ghprCmd.Run(), "error running test command")
	}

	type testCase struct {
		commit string
		name   string
		assert func(t *testing.T, artifact *containerImage, attestation prAttestation)
	}

	testCases := []*testCase{
		{
			name:   "approved pull request with one review",
			commit: commitWithApproval,
			assert: func(t *testing.T, artifact *containerImage, attestation prAttestation) {
				assert.Len(t, attestation.Subject, 2, "attestation should have 2 subjects")
				// first subject is the commit created from the pull request
				assert.Equal(t, attestation.Subject[0].Name, fmt.Sprintf("git+%s.git", githubPrFixtureRepository))
				assert.Equal(t, attestation.Subject[0].Digest, common.DigestSet{
					"sha1": commitWithApproval,
				})
				// second subject is the image
				assert.Equal(t, attestation.Subject[1].Name, testImageName())
				assert.Equal(t, attestation.Subject[1].Digest, common.DigestSet{
					artifact.digest.Algorithm: artifact.digest.Hex,
				})

				assert.WithinDurationf(t, time.Now(), attestation.Predicate.PredicateCreatedAt, time.Minute, "expected attestation to have been created recently")
				assert.Equal(t, &pull_request_v1.Predicate{
					Link:      "https://github.com/liatrio/pr-attestation-fixtures/pull/5",
					Title:     "feat: approved change",
					Author:    "alexashley",
					MergedBy:  "alexashley",
					CreatedAt: parseTime(t, "2023-06-07T20:19:52Z"),
					MergedAt:  parseTime(t, "2023-06-07T20:48:16Z"),
					Base:      "main",
					Head:      "approved",
					Approved:  true,
					Reviewers: []*pull_request_v1.Reviewer{
						{
							Name:       "rcoy-v",
							Approved:   true,
							ReviewLink: "https://github.com/liatrio/pr-attestation-fixtures/pull/5#pullrequestreview-1468532527",
							Timestamp:  parseTime(t, "2023-06-07T20:42:51Z"),
						},
					},
					Contributors: []*pull_request_v1.Contributor{
						{
							Name: "alexashley",
						},
					},
					PredicateCreatedAt: attestation.Predicate.PredicateCreatedAt,
				}, attestation.Predicate)
			},
		},
		{
			name:   "pull request with no reviews",
			commit: commitWithNoReviews,
			assert: func(t *testing.T, artifact *containerImage, attestation prAttestation) {
				assert.False(t, attestation.Predicate.Approved, "pull request was not approved")
				assert.Len(t, attestation.Predicate.Reviewers, 0, "attestation should show no reviewers")
				assert.Len(t, attestation.Predicate.Contributors, 1, "attestation should show a single contributor")
			},
		},
		{
			name:   "changes requested on pull request",
			commit: commitWithChangesRequested,
			assert: func(t *testing.T, artifact *containerImage, attestation prAttestation) {
				assert.False(t, attestation.Predicate.Approved, "pull request was not approved")
				assert.Equal(t, attestation.Predicate.Reviewers, []*pull_request_v1.Reviewer{
					{
						Name:       "rcoy-v",
						Approved:   false,
						ReviewLink: "https://github.com/liatrio/pr-attestation-fixtures/pull/4#pullrequestreview-1468533763",
						Timestamp:  parseTime(t, "2023-06-07T20:43:49Z"),
					},
				})
			},
		},
		{
			name:   "pull request with multiple reviews ending in approval",
			commit: commitWithMultipleReviewsApprovalEndState,
			assert: func(t *testing.T, artifact *containerImage, attestation prAttestation) {
				assert.True(t, attestation.Predicate.Approved, "pull request was approved")
				assert.Equal(t, attestation.Predicate.Reviewers, []*pull_request_v1.Reviewer{
					{
						Name:       "rcoy-v",
						Approved:   true,
						ReviewLink: "https://github.com/liatrio/pr-attestation-fixtures/pull/2#pullrequestreview-1468540321",
						Timestamp:  parseTime(t, "2023-06-07T20:48:28Z"),
					},
				})
			},
		},
		{
			name:   "pull request with multiple reviews ending in changes requested",
			commit: commitWithApprovalMultipleReviewsChangesRequestedEndState,
			assert: func(t *testing.T, artifact *containerImage, attestation prAttestation) {
				assert.False(t, attestation.Predicate.Approved, "pull request was not approved")
				assert.Equal(t, attestation.Predicate.Reviewers, []*pull_request_v1.Reviewer{
					{
						Name:       "rcoy-v",
						Approved:   false,
						ReviewLink: "https://github.com/liatrio/pr-attestation-fixtures/pull/6#pullrequestreview-1468541063",
						Timestamp:  parseTime(t, "2023-06-07T20:49:01Z"),
					},
				})
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newGitHubRecorder(t)
			defer stopRecorder(t, r)

			repo := createGitRepoAtHead(t, tc.commit)

			artifact, err := randomImage()
			assert.NoError(t, err, "error making random image")

			ctx := makeCtx(r, repo)
			runAttestationCmd(t, ctx, artifact)

			signatures, err := verifyImageAttestations(ctx, artifact)
			assert.NoError(t, err, "failed to verify image attestations")

			prAttestations, err := filterAttestations[prAttestation](signatures, prAttestationType)
			assert.Len(t, prAttestations, 1, "expected a single attestation")

			tc.assert(t, artifact, prAttestations[0])
		})
	}

	t.Run("remote url uses SSH", func(t *testing.T) {
		t.Parallel()
		r := newGitHubRecorder(t)
		defer stopRecorder(t, r)

		repo := createGitRepoAtHead(t, commitWithApproval, "git@github.com:liatrio/pr-attestation-fixtures.git")

		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		ctx := makeCtx(r, repo)
		runAttestationCmd(t, ctx, artifact)

		signatures, err := verifyImageAttestations(ctx, artifact)
		assert.NoError(t, err, "failed to verify image attestations")

		prAttestations, err := filterAttestations[prAttestation](signatures, prAttestationType)
		assert.Len(t, prAttestations, 1, "expected a single attestation")

		attestation := prAttestations[0]
		assert.Equal(t, attestation.Subject[0].Name, fmt.Sprintf("git+%s.git", githubPrFixtureRepository))
		assert.Equal(t, attestation.Subject[0].Digest, common.DigestSet{
			"sha1": commitWithApproval,
		})
		assert.True(t, attestation.Predicate.Approved)
	})

	t.Run("remote is invalid", func(t *testing.T) {
		t.Parallel()
		r := newGitHubRecorder(t)
		defer stopRecorder(t, r)

		repo := createGitRepoAtHead(t, commitWithApproval, "foobar")
		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		ctx := makeCtx(r, repo)
		ghprCmd := cmd.GitHubPullRequest{}
		flags := makeGlobalFlags(artifact.digest.String())
		err = ghprCmd.Init(ctx, flags)
		assert.NoError(t, err, "failure initializing test command")

		err = ghprCmd.Run()

		assert.ErrorContains(t, err, "remote url for 'origin' is invalid")
	})

	t.Run("repository has no remotes", func(t *testing.T) {
		r := newGitHubRecorder(t)
		defer stopRecorder(t, r)

		cfg := gitconfig.NewConfig()
		store := memory.NewStorage()
		err := store.SetConfig(cfg)
		assert.NoError(t, err, "error configuring in-memory repository")

		headRef := plumbing.NewReferenceFromStrings(plumbing.HEAD.String(), commitWithApproval)
		err = store.SetReference(headRef)
		assert.NoError(t, err, "error setting reference on in-memory repository")

		repo := &git.Repository{
			Storer: store,
		}

		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		ctx := makeCtx(r, repo)
		ghprCmd := cmd.GitHubPullRequest{}
		flags := makeGlobalFlags(artifact.digest.String())
		err = ghprCmd.Init(ctx, flags)
		assert.NoError(t, err, "failure initializing test command")

		err = ghprCmd.Run()

		assert.ErrorContains(t, err, "remote not found")
	})

	t.Run("commit with no associated pull requests", func(t *testing.T) {
		t.Parallel()

		r := newGitHubRecorder(t)
		defer stopRecorder(t, r)

		repo := createGitRepoAtHead(t, commitWithNoAssociatedPullRequest)

		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		ctx := makeCtx(r, repo)
		runAttestationCmd(t, ctx, artifact)

		_, err = verifyImageAttestations(ctx, artifact)
		assert.ErrorContains(t, err, "no matching attestations")
	})
}
