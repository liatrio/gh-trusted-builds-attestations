#!/usr/bin/env bash

set -euo pipefail

SIGSTORE_SCAFFOLDING_VERSION="v0.6.4"
K8S_VERSION="v1.25.x"

tmpDir=$(mktemp -d)

echo "Using ${tmpDir} for test setup"
cd "${tmpDir}"

curl --fail --remote-name-all -sL \
  "https://github.com/sigstore/scaffolding/releases/download/${SIGSTORE_SCAFFOLDING_VERSION}/{setup-kind.sh,setup-scaffolding-from-release.sh,testrelease.yaml}"

chmod +x setup-kind.sh setup-scaffolding-from-release.sh

echo "Setting up kind cluster"
# TODO: pass --registry-url registry.local:5000
./setup-kind.sh  --k8s-version "${K8S_VERSION}"

echo "Installing scaffolding"
./setup-scaffolding-from-release.sh --release-version "${SIGSTORE_SCAFFOLDING_VERSION}"

echo "Installing OIDC Issuer & Testing Setup"
# copy TUF root to default namespace because the sigstore/scaffolding test jobs will use it
kubectl -n tuf-system get secrets tuf-root -oyaml | sed 's/namespace: .*/namespace: default/' | kubectl apply -f -

kubectl apply -f testrelease.yaml

#echo "Waiting for sign & verify setup test jobs to finish"
#kubectl wait --for=condition=Complete --timeout=180s job/sign-job
#kubectl wait --for=condition=Complete --timeout=180s job/verify-job
#
echo "Finished test setup"
