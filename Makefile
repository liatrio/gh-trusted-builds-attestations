MAKEFLAGS += --silent

default:
	echo No default target

.PHONY: github-pull-request
github-pull-request:
	go run cmd/attestation.go github-pull-request \
		--artifact-digest "sha256:04169a9d1c6b627a7bee1fa2de0459e053c5e14704004492de5c148ea2e1d40d" \
		--artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app" \
		--oidc-issuer-url "https://oauth2.sigstore.dev/auth"

.PHONY: vsa
vsa:
	go run cmd/attestation.go vsa \
		--artifact-digest "sha256:a166d7a90719f74f2a5758116a070b99a0f7602a7772ad8de6ea22a35bb8eb58" \
        --commit-sha "5b25a576d343d7877753b8c2861860f0599749aa" \
        --artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app" \
        --policy-version "v1.1.1" \
        --verifier-id "local-verifier"
