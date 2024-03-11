#!/usr/bin/env bash

set -euo pipefail

if [ -n "${CI-}" ]; then
    export REKOR_URL=$(kubectl -n rekor-system get ksvc rekor -ojsonpath='{.status.url}')
    export FULCIO_URL=$(kubectl -n fulcio-system get ksvc fulcio -ojsonpath='{.status.url}')
    export TUF_MIRROR=$(kubectl -n tuf-system get ksvc tuf -ojsonpath='{.status.url}')
else
    echo "Port-forwarding kourier service"
    kubectl -n kourier-system port-forward service/kourier-internal 8080:80 &
    KUBECTL_PID=$!
    trap "echo 'Stopping port-forward' && kill -9 $KUBECTL_PID" EXIT

    echo "Waiting for port-forwarding to start"
    sleep 3

    # When running locally, use the scaffolding gettoken service. In CI, use the ambient OIDC flow
    export ID_TOKEN=$(curl --fail -s "http://gettoken.default.svc:8080")
fi

# a valid token is only needed when recording new fixtures
export GITHUB_TOKEN="${GITHUB_TOKEN-"invalid"}"
go test -v -count 1 -run ^TestGitHubPullRequestCmd ./...
