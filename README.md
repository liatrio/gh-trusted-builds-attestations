# gh-trusted-builds-attestations

This is an example of how to create custom attestations using `in-toto` and `cosign`.

## Use

Directly from source:
```shell
$ go run main.go <attestation-type> [--flag]
```

Downloaded and extracted binary from [GitHub Releases](https://github.com/liatrio/gh-trusted-builds-attestations/releases):
```shell
$ ./attestation <attestation-type> [--flag]
```

There are also working examples of each command in the [Makefile](Makefile).

### Global Flags

All attestation types may use or require these flags. 

`--fulcio-url`: The Fulcio CA url for keyless signing. Defaults to `https://fulcio.sigstore.dev`.
  Intended only for use with ambient providers like GitHub Actions, as there are no options for overriding the default OIDC settings.

`--rekor-url`: The transparency log URL. Defaults to `https://rekor.sigstore.dev`.

`--oidc-issuer-url`: Defaults to `https://oauth2.sigstore.dev/auth`.

`--oidc-client-id`: Defaults to `sigstore`.

`--id-token`: An optional flag to specify an id token to use for keyless signing.

`--artifact-uri`: **required** URI of the OCI artifact i.e., the subject of the attestation.
ex: `ghcr.io/liatrio/gh-trusted-builds-app`

`--artifact-digest`: **required**  digest of the OCI artifact.
Used for retrieving related artifact attestations, and marking the attestation subject.
ex: `sha256:60bcfdd293baac977357527bbd7ec2b5a7584ce276d33de0a4980c8ace6afd67`

### Attestations

The following attestation types can be created by this app.
Which attestation type to create is given as a subcommand, `./attestation <attestation-type>`. 

#### GitHub Pull Request

- Subcommand: `github-pull-request`
- Predicate type: `https://liatr.io/attestations/github-pull-request/v1`

This attestation type links a Git commit to a pull request, and includes information about the pull request.

It can be used to verify that:
- An author didn't approve their own pull request.
- A minimum threshold of reviewers approved the pull request.
- None of the pull request contributors approved the pull request.

```yaml
_type: https://in-toto.io/Statement/v0.1
predicateType: https://liatr.io/attestations/github-pull-request/v1
subject:
  - name: git+https://github.com/liatrio/gh-trusted-builds-app.git
    digest:
      sha1: e1f1d4396181766e12fca22f2ba856e8154b4304
  - name: ghcr.io/liatrio/gh-trusted-builds-app
    digest:
      sha256: 6c3bf887638f7c0d86731e6208befa1b439e465cb435465d982c50609553b514
predicate:
  link: https://github.com/liatrio/gh-trusted-builds-app/pull/1
  title: 'docs: remove extra newline'
  author: rcoy-v
  mergedBy: rcoy-v
  createdAt: '2023-05-22T15:27:05Z'
  mergedAt: '2023-05-22T15:27:27Z'
  base: main
  head: rcoy-v-patch-1
  approved: true
  reviewers:
    - name: alexashley
      approved: true
      reviewLink: >-
        https://github.com/liatrio/gh-trusted-builds-app/pull/1#pullrequestreview-1436887240
      timestamp: '2023-05-22T15:27:18Z'
  contributors:
    - name: rcoy-v
  predicateCreatedAt: '2023-05-22T15:28:48.369418041Z'
```

The attestor expects to run inside a Git repository, as it will use the `HEAD` sha to lookup pull requests.
For development, you can set the environment variable `GH_PR_ATTESTOR_SHA_OVERRIDE` to use a different SHA; however, this will not work in CI servers
that set the `CI` environment variable.

##### Environment Variables

`GITHUB_TOKEN`: A GitHub token with access to read pull request information from repository of the commit.

#### Verification Attestation Summary

- Subcommand: `vsa`
- Predicate type: `https://slsa.dev/verification_summary/v0.2` 

This creates a [SLSA Verification Attestation Summary](https://slsa.dev/verification_summary).

The following process is used to create a VSA:

1. Retrieve all attestations related to the artifact which is the subject of the VSA, from Rekor.
   The attestations include:
   1. Artifact-related e.g., Trivy scans.
   1. Source-related e.g., Pull request state.
1. Provide all the collected attestations as input to the governance policy from [liatrio/gh-trusted-builds-policy](https://github.com/liatrio/gh-trusted-builds-policy).
1. Craft the in-toto attestation, using the policy results, provided attestations, and artifact digest.
1. Sign the attestation, using either the KMS or Fulcio methods configured via flags.
1. Upload the VSA to Rekor.

##### Command Flags

`--debug`: Emit print logs from policy evaluation. Defaults to `false`

`--policy-query`: The Rego query to use when evaluating the policy. Defaults to `data.governance.allow`.

`--policy-url`: Location of policy bundle that will be used to determine VSA result.
Supports http(s) urls for unauthenticated external downloads.
Absolute and relative paths can be used for an existing, local bundle or directory.
It's also possible to download files from a particular GitHub commit

Examples:

- `https://github.com/liatrio/gh-trusted-builds-policy/releases/download/v1.4.0/bundle.tar.gz`
- `bundle.tar.gz`
- `../bundle.tar.gz`
- `/Users/myhome/bundle.tar.gz`
- `../policy`
- `https://github.com/liatrio/gh-trusted-builds-policy/tree/ef3194db6ca9a7a4b030686e4669c45db360a0c2/policy`

`--signer-identities-query`: A Rego query that should specify the expected attestation signer identities. The result should be a list of objects that can be unmarshalled into `cosign.Identity`. Defaults to `data.governance.signer_identities`.

```rego
[
    {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectRegExp": `^https://github\.com/liatrio/gh-trusted-builds-workflows/\.github/workflows/build-and-push\.yaml@.*`,
    }
]
```

`--verifier-id`: ID of entity verifying the policy for the VSA.

#### Version

- Subcommand: `version`

Prints the build version information of the application.

## Local Development

In order to build the project, you'll need Go 1.22+.

Export any environment variables as described for the command being tested.

Each attestor should have a [Makefile](Makefile) target to invoke it, like this: `make github-pull-request`

Running any `vsa` commands will require that you have authenticated against the artifact-uri already. (if you are providing a ghcr.io container registry repo, then make sure to `docker login ghcr.io` before running commands)

### Integration Tests

This application includes a suite of integration tests that verify the different attestation commands. In order to run the tests, you'll need to have these tools installed locally:

- [`docker`](https://www.docker.com/products/docker-desktop/)
- [`kind`](https://kind.sigs.k8s.io/)
- [`yq`](https://github.com/mikefarah/yq)
- [`kubectl`](https://kubernetes.io/docs/reference/kubectl/)

First, add the following entries to `/etc/hosts`:

```
127.0.0.1 registry.local
127.0.0.1 rekor.rekor-system.svc
127.0.0.1 fulcio.fulcio-system.svc
127.0.0.1 ctlog.ctlog-system.svc
127.0.0.1 gettoken.default.svc
127.0.0.1 tuf.tuf-system.svc
```

Next, run `make test-setup`. This will download resources from the Sigstore [scaffolding repo](https://github.com/sigstore/scaffolding), stand up a kind cluster, and deploy Rekor & Fulcio.
It will also create a TUF root that's used by the tests. The setup should take 5-10 minutes. It only needs to be run once.

⚠️ WARNING: The tests run the equivalent of `cosign initialize`, meaning that if you have a custom TUF root configured, it will be temporarily overwritten in place of the TUF root created
by the scaffolding setup. The tests will attempt to save the TUF root in `~/.sigstore-backup` before running, and restore it after. If the tests fail to restore the custom root, you can remove it by running `rm -rf ~/.sigstore` and `mv ~/.sigstore-backup ~/.sigstore`.
If you're not using a custom TUF root, deleting the `~/.sigstore` directory should suffice.

Next, run `make test` to start the tests. Unfortunately, there's some noise in the output, but you can usually ignore these logs about port-forwarding:

> Handling connection for 8080

as well as the logs about issues with the TUF root metadata:

```
**Warning** Custom metadata not configured properly for target tsa_intermediate_0.crt.pem, skipping target
**Warning** Custom metadata not configured properly for target tsa_leaf.crt.pem, skipping target
```

You'll also see certificates printed in the output from keyless signing, these are generated during the tests:

```
Successfully verified SCT...
using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIIExTCCAq2gAwIBAgIUa1P4DGiAjiFev2fx+KCZ2NrK9VMwDQYJKoZIhvcNAQEL
BQAwfjEMMAoGA1UEBhMDVVNBMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
...
```

Lastly, once you're done testing, you can run `make test-teardown` to destroy the kind cluster. Optionally, you can also remove the entries from `/etc/hosts` that were added in the first step.

#### GitHub API

The `github-pull-request` attestor uses the GitHub API to populate the attestation.
In order to avoid depending on the live GitHub.com service, the tests use [`go-vcr`](https://github.com/dnaeon/go-vcr) to replay past responses.
These responses are stored in `test/fixtures/github`, organized by test name.

The fixture data is from [`liatrio/pr-attestation-fixtures`](https://github.com/liatrio/pr-attestation-fixtures).
If you need to add a fixture for a new scenario, you can make changes in that repository.

Next, set `GITHUB_TOKEN` to a fine-grained personal access token with the following scopes for the `liatrio/pr-attestation-fixtures` repository:
 - `contents` (read-only)
 - `metadata` (read-only)
 - `pull-requests` (read-only)

Finally, change the mode on GitHub API recorder to `recorder.ModeRecordOnce` (if you're adding a new test) or `recorder.ModeReplayWithNewEpisodes` (if you're making changes to an existing test).

```go
r, err := recorder.NewWithOptions(&recorder.Options{
    CassetteName:  filepath.Join("fixtures", "github", t.Name()),
    Mode:          recorder.ModeRecordOnce,
    RealTransport: oauth2Transport,
})
```
