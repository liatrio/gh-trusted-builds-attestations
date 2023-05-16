MAKEFLAGS += --silent

default:
	echo No default target

.PHONY: pull-request
pull-request:
	go run cmd/attestor.go \
		--rekor-url "https://rekor.sec-guild-dev.private.northcentralus.azmk8s.io" \
		--kms-key-uri "azurekms://ag-poc-platform-c2wn.vault.azure.net/platform-team-cosign" \
		--attestor "github-pull-request"

.PHONY: generic
generic:
	go run cmd/attestor.go \
		--rekor-url "https://rekor.sec-guild-dev.private.northcentralus.azmk8s.io" \
		--kms-key-uri "azurekms://ag-poc-platform-c2wn.vault.azure.net/platform-team-cosign" \
		--attestation-path "hack/gitsign-attestation.json" \
		--attestor "generic"

.PHONY: vsa
vsa:
	go run cmd/attestation.go vsa \
		--artifact-digest "5eef5125860381d04714c496f440a1d8eb339e34d3c128da5a5b14da70662eed" \
        --commit-sha "e8cfdb543d6031a2fbdcf51a395e030f1727de77" \
        --artifact-uri "agplatformrnim.azurecr.io/liatrio/gh-trusted-builds-app" \
        --policy-version "v1.1.1" \
        --verifier-id "local-verifier" \
        --kms-key-uri "azurekms://ag-poc-security-OtfL.vault.azure.net/security-team-cosign" \
        --rekor-url "https://rekor.sec-guild-dev.private.northcentralus.azmk8s.io"
