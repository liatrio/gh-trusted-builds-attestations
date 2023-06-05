MAKEFLAGS += --silent

BUILD := $(shell git describe --dirty)
LDFLAGS=-ldflags "-X github.com/liatrio/gh-trusted-builds-attestations/build.Version=$(BUILD)"

.PHONY: build
build: clean
	go build $(LDFLAGS) -o attestation

.PHONY: clean
clean:
	rm -f attestation

.PHONY: github-pull-request
github-pull-request:
	go run $(LDFLAGS) main.go github-pull-request \
		--artifact-digest "sha256:6c3bf887638f7c0d86731e6208befa1b439e465cb435465d982c50609553b514" \
		--artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app"

.PHONY: vsa
vsa:
	go run $(LDFLAGS) main.go vsa \
		--artifact-digest "sha256:5f3b045689a0c948418c2dc52086102f59aaeba82784f099f130081c8cac9ed0" \
        --artifact-uri "ghcr.io/liatrio/gh-trusted-builds-app" \
        --policy-url "https://github.com/liatrio/gh-trusted-builds-policy/releases/download/v1.3.0/bundle.tar.gz" \
        --verifier-id "local-verifier"

.PHONY: version
version:
	go run $(LDFLAGS) main.go version

.PHONY: help
help:
	go run $(LDFLAGS) main.go help