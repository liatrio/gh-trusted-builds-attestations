#!/usr/bin/env bash

set -euo pipefail

echo "Removing kind cluster"
kind delete clusters kind

echo "Stopping registry container"
docker stop registry.local
docker rm registry.local

echo "Deleting kind network"
docker network rm kind

echo "Deleting TUF root"
rm test/root.json
