#!/usr/bin/env bash

set -euo pipefail

export REKOR_URL=$(kubectl -n rekor-system get ksvc rekor -ojsonpath='{.status.url}')
export FULCIO_URL=$(kubectl -n fulcio-system get ksvc fulcio -ojsonpath='{.status.url}')
export TUF_MIRROR=$(kubectl -n tuf-system get ksvc tuf -ojsonpath='{.status.url}')

# When running locally, use the scaffolding gettoken service. In CI, use the ambient OIDC flow
if [ -z "${CI-}" ]; then
  GET_TOKEN_ENDPOINT=$(kubectl get ksvc gettoken -ojsonpath='{.status.url}')
  export ID_TOKEN=$(curl --fail -s "${GET_TOKEN_ENDPOINT}")
fi

# a valid token is only needed when recording new fixtures
export GITHUB_TOKEN=${GITHUB_TOKEN-"invalid"}
go test -v -count 1 ./...
