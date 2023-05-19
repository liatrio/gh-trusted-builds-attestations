MAKEFLAGS += --silent

default:
	echo No default target

.PHONY: github-pull-request
github-pull-request:
	go run cmd/attestation.go github-pull-request \
		--artifact-digest "sha256:90dd2b640aac51d062f4f29bf1f59360e4ad2961939f32c2b93cdd96a2cd3615" \
		--artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app"

.PHONY: vsa
vsa:
	go run cmd/attestation.go vsa \
		--artifact-digest "sha256:90dd2b640aac51d062f4f29bf1f59360e4ad2961939f32c2b93cdd96a2cd3615" \
        --commit-sha "5b25a576d343d7877753b8c2861860f0599749aa" \
        --artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app" \
        --policy-version "v1.1.1" \
        --verifier-id "local-verifier"
