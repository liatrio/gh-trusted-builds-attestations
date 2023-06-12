#!/usr/bin/env bash

set -euo pipefail

SIGSTORE_SCAFFOLDING_VERSION="v0.6.4"
K8S_VERSION="v1.25.x"
REGISTRY_URL="registry.local:5001"

tmpDir=$(mktemp -d)

echo "Using ${tmpDir} for test setup"
pushd "${tmpDir}"

curl --fail --remote-name-all -sL \
  "https://github.com/sigstore/scaffolding/releases/download/${SIGSTORE_SCAFFOLDING_VERSION}/{setup-kind.sh,setup-scaffolding-from-release.sh,testrelease.yaml}"

chmod +x setup-kind.sh setup-scaffolding-from-release.sh

echo "Setting up kind cluster"
./setup-kind.sh  --k8s-version "${K8S_VERSION}" --registry-url "${REGISTRY_URL}"

echo "Installing scaffolding"
./setup-scaffolding-from-release.sh --release-version "${SIGSTORE_SCAFFOLDING_VERSION}"

echo "Installing OIDC Issuer & Testing Setup"

# copy TUF root to default namespace because the sigstore/scaffolding test jobs will use it
# https://github.com/sigstore/scaffolding/blob/84f4140ad89fd7ea270f9862941228b2d0fa72e6/actions/setup/action.yml#L111-L112
kubectl -n tuf-system get secrets tuf-root -oyaml | sed 's/namespace: .*/namespace: default/' | kubectl apply -f -

# overwrite the hard-coded registry in the release
# https://github.com/sigstore/scaffolding/pull/547
sed -i.bak "s/registry.local:5000/${REGISTRY_URL}/g" testrelease.yaml

kubectl apply -f testrelease.yaml

echo "Waiting for sign & verify setup test jobs to finish"
kubectl wait --for=condition=Complete --timeout=180s job/sign-job
kubectl wait --for=condition=Complete --timeout=180s job/verify-job

popd

cp "${tmpDir}/root.json" "test/root.json"

echo "Finished test setup"
