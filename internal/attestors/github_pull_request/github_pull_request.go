package github_pull_request

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"

	"github.com/google/go-github/v60/github"
	"github.com/in-toto/in-toto-golang/in_toto"
	pull_request_v1 "github.com/liatrio/gh-trusted-builds-attestations/internal/attestations/github/pull_request/v1"
	gh "github.com/liatrio/gh-trusted-builds-attestations/internal/github"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/util"
)

const (
	GitHubPullRequestAttestorName     = "github-pull-request"
	GitHubReviewCommentedState        = "COMMENTED"
	GitHubReviewChangesRequestedState = "CHANGES_REQUESTED"
	GitHubReviewApprovedState         = "APPROVED"
)

type ctxKey struct{}

var (
	GitRepositoryOverrideCtxKey = ctxKey{}
)

type Attestor struct {
	github gh.Client
	signer sigstore.Signer
}

func NewAttestor(ctx context.Context, opts *config.GitHubPullRequestCommandOptions) (*Attestor, error) {
	githubClient, err := gh.New(ctx, opts.GitHubToken)
	if err != nil {
		return nil, err
	}

	signer, err := sigstore.NewSigner(opts.RekorUrl.String())
	if err != nil {
		return nil, err
	}

	return &Attestor{
		github: githubClient,
		signer: signer,
	}, nil
}

func (g *Attestor) Attest(ctx context.Context, opts *config.GitHubPullRequestCommandOptions) error {
	localRepo, err := openLocalRepository(ctx)
	if err != nil {
		return err
	}

	slug, err := g.github.GetRepositorySlugFromRemote(localRepo)
	if err != nil {
		return err
	}

	sha, err := localRepo.Head()
	if err != nil {
		return fmt.Errorf("error reading HEAD sha: %s", err)
	}

	// for local development it's useful to be able to control the commit we're attesting, but we don't want to do this in CI
	devOverrideSha := os.Getenv("GH_PR_ATTESTOR_SHA_OVERRIDE")
	if devOverrideSha != "" && !inCI() {
		sha = localDevSha(devOverrideSha)
	}

	log.Printf("Looking for pull requests in %s at commit %s on %s \n", slug.Name(), sha.Hash().String(), sha.Name().Short())
	pullRequests, err := g.github.ListPullRequestsWithCommit(ctx, slug, sha.Hash().String())
	if err != nil {
		return err
	}

	log.Printf("Found %d pull request(s) associated with commit %s\n", len(pullRequests), sha.Hash().String())
	if len(pullRequests) == 0 {
		log.Println("No associated pull requests, skipping attestation creation")
		return nil
	}

	for _, pull := range pullRequests {
		if pull.GetState() != "closed" {
			continue
		}

		// fetch the pull request to get full details
		pr, err := g.github.GetPullRequest(ctx, slug, pull.GetNumber())
		if err != nil {
			return err
		}

		if !pr.GetMerged() {
			continue
		}

		attestation, err := g.createAttestation(ctx, slug, pr)
		if err != nil {
			return err
		}

		// include the image in the list of subjects to assist with verification
		attestation.Subject = append(attestation.Subject, in_toto.Subject{
			Name: opts.ArtifactUri,
			Digest: common.DigestSet{
				opts.ArtifactDigest.Algorithm: opts.ArtifactDigest.Hex,
			},
		})

		payload, err := json.Marshal(attestation)
		if err != nil {
			return fmt.Errorf("error marshalling attestation json: %v", err)
		}
		logEntry, err := g.signer.SignInTotoAttestation(ctx, payload, opts.KeyOpts(), opts.FullArtifactId())
		if err != nil {
			return err
		}

		log.Printf("Uploaded attestation with log index: %d\n", *logEntry.LogIndex)
	}

	return nil
}

func (g *Attestor) Name() string {
	return GitHubPullRequestAttestorName
}

func (g *Attestor) createAttestation(ctx context.Context, slug *gh.RepositorySlug, pr *github.PullRequest) (*in_toto.Statement, error) {
	commits, err := g.github.ListPullRequestCommits(ctx, slug, pr.GetNumber())
	if err != nil {
		return nil, err
	}

	contributorNames := util.NewStringSet()
	for _, commit := range commits {
		contributorNames.Add(commit.GetAuthor().GetLogin())
	}

	contributors := []*pull_request_v1.Contributor{}
	for _, contributor := range contributorNames.Items() {
		contributors = append(contributors, &pull_request_v1.Contributor{
			Name: contributor,
		})
	}

	reviews, err := g.github.ListPullRequestReviews(ctx, slug, pr.GetNumber())
	if err != nil {
		return nil, err
	}

	author := pr.GetUser().GetLogin()
	log.Printf("Found %d reviews on pull request #%d by %s\n", len(reviews), pr.GetNumber(), author)
	reviewers := map[string][]*github.PullRequestReview{}

	for _, r := range reviews {
		reviewer := r.GetUser().GetLogin()

		switch r.GetState() {
		case GitHubReviewCommentedState:
			continue
		case GitHubReviewApprovedState, GitHubReviewChangesRequestedState:
			if _, ok := reviewers[reviewer]; ok {
				reviewers[reviewer] = append(reviewers[reviewer], r)
			} else {
				reviewers[reviewer] = []*github.PullRequestReview{r}
			}
		default:
			continue
		}
	}

	log.Printf("Total of %d reviewers on pull request #%d", len(reviewers), pr.GetNumber())

	subject := &pull_request_v1.Subject{
		RepositoryLink: fmt.Sprintf("git+%s.git", pr.GetHead().GetRepo().GetHTMLURL()),
		CommitSha:      pr.GetMergeCommitSHA(),
	}

	prReviewers := []*pull_request_v1.Reviewer{}
	approvalCount := 0
	for reviewer, prReviews := range reviewers {
		sort.Slice(prReviews, func(i, j int) bool {
			a := prReviews[i]
			b := prReviews[j]

			return a.GetSubmittedAt().After(b.GetSubmittedAt().Time)
		})

		finalReview := prReviews[0]
		approved := finalReview.GetState() == GitHubReviewApprovedState
		if approved {
			approvalCount++
		}
		prReviewers = append(prReviewers, &pull_request_v1.Reviewer{
			Name:       reviewer,
			Approved:   approved,
			ReviewLink: finalReview.GetHTMLURL(),
			Timestamp:  finalReview.GetSubmittedAt().Time,
		})
	}

	predicate := &pull_request_v1.Predicate{
		Link:               pr.Links.HTML.GetHRef(),
		Title:              pr.GetTitle(),
		Author:             author,
		Approved:           approvalCount > 0 && approvalCount == len(reviewers),
		MergedBy:           pr.GetMergedBy().GetLogin(),
		CreatedAt:          pr.GetCreatedAt().Time,
		MergedAt:           pr.GetMergedAt().Time,
		Base:               pr.GetBase().GetRef(),
		Head:               pr.GetHead().GetRef(),
		Contributors:       contributors,
		Reviewers:          prReviewers,
		PredicateCreatedAt: time.Now().UTC(),
	}

	return pull_request_v1.Attestation(subject, predicate), nil
}

func inCI() bool {
	return os.Getenv("CI") != ""
}

func localDevSha(sha string) *plumbing.Reference {
	return plumbing.NewReferenceFromStrings("refs/heads/main", sha)
}

func openLocalRepository(ctx context.Context) (*git.Repository, error) {
	if repo, ok := ctx.Value(GitRepositoryOverrideCtxKey).(*git.Repository); ok {
		return repo, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error reading current directory: %v", err)
	}
	return git.PlainOpen(wd)
}
