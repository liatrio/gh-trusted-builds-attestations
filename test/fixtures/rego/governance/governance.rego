package governance

env := opa.runtime().env

local_signer_identities := [
    {
        "issuer": "https://kubernetes.default.svc.cluster.local",
        "subject": "https://kubernetes.io/namespaces/default/serviceaccounts/default",
    }
]

ci_signer_identities := [
    {
        "issuer": env["KEYLESS_ISSUER"],
        "subject": env["KEYLESS_SUBJECT"],
    }
]

always_allow {
    true
}

always_deny {
    false
}
