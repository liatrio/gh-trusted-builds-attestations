package governance

local_signer_identities := [
    {
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "subject": "https://kubernetes.io/namespaces/default/serviceaccounts/default",
    }
]

ci_signer_identities := [
    {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectRegExp": `^https://github\.com/liatrio/gh-trusted-builds-attestations/\.github/workflows/.*\.yaml@.*`,
    }
]

always_allow {
    true
}

always_deny {
    false
}
