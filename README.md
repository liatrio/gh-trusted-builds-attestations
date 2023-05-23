# gh-trusted-builds-attestations

This is an example of how to create custom attestations using `in-toto` and `cosign`.

## Use

Directly from source:
```shell
$ go run cmd/attestation.go <attestation-type> [--flag]
```

Downloaded and extracted binary from [GitHub Releases](https://github.com/liatrio/gh-trusted-builds-attestations/releases):
```shell
$ ./attestation <attestation-type> [--flag]
```

### Global Flags

All attestation types may use or require these flags. 

`--fulcio-url`: The Fulcio CA url for keyless signing. Defaults to `https://fulcio.sigstore.dev`.
  Intended only for use with ambient providers like GitHub Actions, as there are no options for overriding the default OIDC settings.

`--rekor-url`: The transparency log URL. Defaults to `https://rekor.sigstore.dev`.

`--oidc-issuer-url`: Defaults to `https://oauth2.sigstore.dev/auth`.

`--oidc-client-id`: Defaults to `sigstore`.

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

`--policy-url`: Location of policy bundle that will be used to determine VSA result.
Supports http(s) urls for unauthenticated external downloads.
Absolute and relative paths can be used for an existing, local bundle.

Examples:

- `https://github.com/liatrio/gh-trusted-builds-policy/releases/download/v1.1.1/bundle.tar.gz`
- `bundle.tar.gz`
- `../bundle.tar.gz`
- `/Users/myhome/bundle.tar.gz`

`--verifier-id`: ID of entity verifying the policy for the VSA.


## Local Development

In order to build the project, you'll need Go 1.20+.

Export any environment variables as described for the command being tested.

Each attestor should have a [Makefile](Makefile) target to invoke it, like this: `make github-pull-request`
