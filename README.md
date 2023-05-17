# custom-attestations-poc

This is an example of how to create custom attestations using `in-toto` and `cosign`.

## Use

```shell
$ go run cmd/attestor.go \
    --attestor github-pull-request \
    --rekor-url https://rekor.example.com \
    --kms-key-uri azurekms://example.vault.azure.net/cosign
```

The attestor is expecting these flags:
- `--attestor`: Name of the attestor to use
- `--kms-key-uri`: An cloud provider KMS URI, in [`cosign`'s expected format](https://docs.sigstore.dev/cosign/kms_support/). Optional if a Fulcio URL is provided
- `--fulcio-url`: The Fulcio CA url. If this is provided, the attestor will attempt to use keyless signing. Intended only for use with ambient providers like GitHub Actions, as there are no options for overriding the default OIDC settings.
- `--rekor-url`: The transparency log URL

## Attestations

### GitHub Pull Request

Predicate type: `https://liatr.io/attestations/github-pull-request/v1`

This attestation type links a Git commit to a pull request, and includes information about the pull request.
It can be used to verify that an author didn't approve their own pull request, that a minimum threshold of reviewers approved the pull request,
or that none of the pull request contributors approved the pull request.

The `approved` field is true only when the number of approvals is equal to the number of reviewers (excluding comment-only reviews).

```yaml
_type: https://in-toto.io/Statement/v0.1
predicateType: https://liatr.io/attestations/github-pull-request/v1
subject:
  - name: git+https://github.com/liatrio/custom-attestations-poc.git
    digest:
      sha1: ccdb1357fc52fea7cf8204b5f3c8d6eb4e1b8846
predicate:
  link: https://github.com/liatrio/custom-attestations-poc/pull/2
  title: 'docs: save Microsoft a few bytes'
  author: alexashley
  mergedBy: alexashley
  createdAt: '2023-04-24T19:07:47Z'
  mergedAt: '2023-04-24T19:15:18Z'
  base: main
  head: important-work
  approved: true
  reviewers:
    - name: rcoy-v
      approved: true
      reviewLink: >-
        https://github.com/liatrio/custom-attestations-poc/pull/2#pullrequestreview-1398643433
      timestamp: '2023-04-24T19:12:11Z'
  contributors:
    - name: alexashley
  predicateCreatedAt: '2023-04-25T19:52:43.3419Z'
```

The attestor expects to run inside a Git repository, as it will use the `HEAD` sha to lookup pull requests.
For development, you can set the environment variable `GH_PR_ATTESTOR_SHA_OVERRIDE` to use a different SHA; however, this will not work in CI servers
that set the `CI` environment variable.

## Local Development

In order to build the project, you'll need Go 1.20+.

You'll also need a GitHub personal access token, which should be passed by setting the `GITHUB_TOKEN` environment variable.

Each attestor should have a Make target to invoke it, like this: `make github-pull-request`


# gh-trusted-builds-vsa

Go application for creating [SLSA Verification Attestation Summaries](https://slsa.dev/verification_summary) in trusted
CI workflows.

The application uses the following process to create a VSA:

1. Retrieve all attestations related to the artifact which is the subject of the VSA, from Rekor.
   The attestations include:
    1. Artifact-related e.g., Trivy scans.
    1. ource-related e.g., Pull request state.
1. Provide all of the collected attestations as input to the governance policy from [liatrio/gh-trusted-builds-policy](https://github.com/liatrio/gh-trusted-builds-policy).
1. Craft the in-toto attestation, using the policy results, provided attestations, and artifact digest.
1. Sign the attestation, using either the KMS or Fulcio methods configured via flags.
1. Upload the VSA to Rekor.

## Usage

The app is published as a GitHub release.

Example running of the built command:
```bash
vsa \
  --artifact-digest "60bcfdd293baac977357527bbd7ec2b5a7584ce276d33de0a4980c8ace6afd67" \
  --commit-sha "24d01c0c9f456f0d0fac8de7f18dc09d5d554ce9" \
  --artifact-uri "agplatformrnim.azurecr.io/liatrio/gh-trusted-builds-app" \
  --policy-version "v1.1.1" \
  --verifier-id "local-verifier" \
  --kms-key-ref "azurekms://ag-poc-security-OtfL.vault.azure.net/security-team-cosign"
```

### Environment Variables

- `GITHUB_TOKEN`: A GitHub token with access to read releases from https://github.com/liatrio/gh-trusted-builds-policy.

### Command Flags

`--artifact-digest`: Sha256 digest of the OCI artifact.
Used for retrieving related artifact attestations, and marking the VSA subject.
ex: `60bcfdd293baac977357527bbd7ec2b5a7584ce276d33de0a4980c8ace6afd67`

`--artifact-uri`: URI of the OCI artifact i.e., the subject of the VSA.
ex: `agplatformrnim.azurecr.io/liatrio/gh-trusted-builds-app`

`--commit-sha`: Sha1 git commit that the artifact was built from.
Used for retrieving source attestations related to the artifact.
ex: `24d01c0c9f456f0d0fac8de7f18dc09d5d554ce9`

`--fulcio-url`: Fulcio server URL.
Provide if using keyless signing of VSA.

`--kms-key-ref`: KMS Key Id.
Provde if using KMS service for signing the VSA.
ex: `azurekms://ag-poc-security-OtfL.vault.azure.net/security-team-cosign`

`--policy-version`: GitHub release version of the governance policy to download from [gh-trusted-builds-policy](https://github.com/liatrio/gh-trusted-builds-policy).
This is the OPA bundle that will be used at runtime to determine the VSA `verification_result`.
ex: `v1.0.0`

`--rekor-url`: Rekor server URL (default `https://rekor.sec-guild-dev.private.northcentralus.azmk8s.io`).
This is where attestations are retrieved from to provide to the governance policy, as well as where the VSA is uploaded.

`--verifier-id`: ID of entity verifying the policy for the VSA.

## Local

```bash
export GITHUB_TOKEN="PAT for liatrio/gh-trusted-builds-policy read release"
make vsa
```