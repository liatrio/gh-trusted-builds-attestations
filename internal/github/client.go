package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

const (
	pullRequestFilter = "closed"
)

type ctxKey struct{}

var (
	GitHubHttpClientCtxKey = ctxKey{}
	ErrMissingOriginRemote = errors.New("remote 'origin' is not configured")
	ErrInvalidRemoteUrl    = errors.New("remote url for 'origin' is invalid")
	ErrNoGitHubToken       = errors.New("must specify a GitHub token using the GITHUB_TOKEN environment variable")
	ErrNoRepoSlug          = errors.New("unable to determine GitHub repository slug")
)

type RepositorySlug struct {
	Repo  string
	Owner string
}

func (s *RepositorySlug) Name() string {
	return fmt.Sprintf("%s/%s", s.Owner, s.Repo)
}

type Client interface {
	GetRepositorySlugFromRemote(repository *git.Repository) (*RepositorySlug, error)
	ListPullRequestsWithCommit(ctx context.Context, slug *RepositorySlug, sha string) ([]*github.PullRequest, error)
	GetPullRequest(ctx context.Context, slug *RepositorySlug, number int) (*github.PullRequest, error)
	ListPullRequestCommits(ctx context.Context, slug *RepositorySlug, number int) ([]*github.RepositoryCommit, error)
	ListPullRequestReviews(ctx context.Context, slug *RepositorySlug, number int) ([]*github.PullRequestReview, error)
	GetRepositoryArchiveAtRef(ctx context.Context, slug *RepositorySlug, ref string) ([]byte, error)
}

type githubClient struct {
	github *github.Client
}

func New(ctx context.Context, token string) (Client, error) {
	if token == "" {
		return nil, ErrNoGitHubToken
	}
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	httpClient := oauth2.NewClient(ctx, ts)

	if httpClientOverride, ok := ctx.Value(GitHubHttpClientCtxKey).(*http.Client); ok {
		httpClient = httpClientOverride
	}

	client := github.NewClient(httpClient)

	return &githubClient{
		github: client,
	}, nil
}

func (g *githubClient) GetRepositorySlugFromRemote(repository *git.Repository) (*RepositorySlug, error) {
	var slug string

	remote, err := repository.Remote(git.DefaultRemoteName)
	if err != nil {
		return nil, fmt.Errorf("error reading remote: %v", err)
	}
	if len(remote.Config().URLs) == 0 {
		return nil, ErrMissingOriginRemote
	}

	rawRemoteUrl := remote.Config().URLs[0]
	log.Printf("Examining remote '%s'\n", rawRemoteUrl)

	if strings.HasPrefix(rawRemoteUrl, "https://") {
		remoteUrl, err := url.ParseRequestURI(rawRemoteUrl)
		if err != nil {
			return nil, fmt.Errorf("error parsing remote url: %v", err)
		}
		slug = strings.TrimPrefix(remoteUrl.Path, "/")
	} else if strings.HasSuffix(rawRemoteUrl, git.GitDirName) {
		startIndex := strings.Index(rawRemoteUrl, ":")
		if startIndex < 0 {
			return nil, ErrInvalidRemoteUrl
		}
		endIndex := strings.Index(rawRemoteUrl, git.GitDirName)
		slug = rawRemoteUrl[startIndex+1 : endIndex]
	} else {
		return nil, ErrInvalidRemoteUrl
	}

	owner, repo, _ := strings.Cut(slug, "/")
	if owner == "" || repo == "" {
		return nil, ErrNoRepoSlug
	}

	return &RepositorySlug{
		Repo:  repo,
		Owner: owner,
	}, nil
}

func (g *githubClient) ListPullRequestsWithCommit(ctx context.Context, slug *RepositorySlug, sha string) ([]*github.PullRequest, error) {
	endpoint := func(opts *github.ListOptions) ([]*github.PullRequest, *github.Response, error) {
		return g.github.PullRequests.ListPullRequestsWithCommit(ctx, slug.Owner, slug.Repo, sha, opts)
	}

	pulls, err := paginate(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error discovering associated pull requests: %v", err)
	}

	return pulls, nil
}

func (g *githubClient) GetPullRequest(ctx context.Context, slug *RepositorySlug, number int) (*github.PullRequest, error) {
	pr, _, err := g.github.PullRequests.Get(ctx, slug.Owner, slug.Repo, number)
	if err != nil {
		return nil, fmt.Errorf("error retrieving pull request: %v", err)
	}

	return pr, nil
}

func (g *githubClient) ListPullRequestCommits(ctx context.Context, slug *RepositorySlug, number int) ([]*github.RepositoryCommit, error) {
	endpoint := func(opts *github.ListOptions) ([]*github.RepositoryCommit, *github.Response, error) {
		return g.github.PullRequests.ListCommits(ctx, slug.Owner, slug.Repo, number, opts)
	}

	commits, err := paginate(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error listing commits for pull request: %v", err)
	}

	return commits, nil
}

func (g *githubClient) ListPullRequestReviews(ctx context.Context, slug *RepositorySlug, number int) ([]*github.PullRequestReview, error) {
	endpoint := func(opts *github.ListOptions) ([]*github.PullRequestReview, *github.Response, error) {
		return g.github.PullRequests.ListReviews(ctx, slug.Owner, slug.Repo, number, opts)
	}

	reviews, err := paginate(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error listing pull request reviews: %v", err)
	}

	return reviews, nil
}

func (g *githubClient) GetRepositoryArchiveAtRef(ctx context.Context, slug *RepositorySlug, ref string) ([]byte, error) {
	archiveLocation, _, err := g.github.Repositories.GetArchiveLink(ctx, slug.Owner, slug.Repo, github.Tarball, &github.RepositoryContentGetOptions{
		Ref: ref,
	}, 0)

	if err != nil {
		return nil, err
	}

	response, err := g.github.Client().Get(archiveLocation.String())
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}

	defer response.Body.Close()

	archive, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return archive, nil
}

type paginatedEndpoint[T any] func(*github.ListOptions) ([]*T, *github.Response, error)

func paginate[T any](endpoint paginatedEndpoint[T]) ([]*T, error) {
	opts := &github.ListOptions{}
	var values []*T

	for {
		page, response, err := endpoint(opts)
		if err != nil {
			return nil, err
		}

		values = append(values, page...)

		if response.NextPage == 0 {
			break
		}
		opts.Page = response.NextPage
	}

	return values, nil
}
