#!/usr/bin/env bash

set -euo pipefail

CLUSTER_NAME="kind"
REGISTRY_NAME="registry.local"
TUF_ROOT="test/root.json"

for cluster in $(kind get clusters); do
  if [[ "$cluster" == "${CLUSTER_NAME}" ]]; then
    echo "Removing kind cluster"
    kind delete clusters kind
  fi
done

registryContainer=$(docker ps -q --filter "name=${REGISTRY_NAME}")
if [[ -n "${registryContainer}" ]]; then
    echo "Stopping registry container"
    docker stop "${registryContainer}"
    docker rm "${registryContainer}"
fi

dockerNetwork=$(docker network ls -q --filter name="${CLUSTER_NAME}")

if [[ -n "${dockerNetwork}" ]]; then
  echo "Deleting kind network"
  docker network rm "${dockerNetwork}"
fi

if [[ -f "${TUF_ROOT}" ]]; then
  echo "Deleting TUF root"
  rm "${TUF_ROOT}"
fi
