package intoto

import (
	"fmt"
	"net/url"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v0"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/sigstore/rekor/pkg/generated/models"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func verificationResult(passed bool) string {
	if passed {
		return "PASSED"
	}

	return "FAILED"
}

func CreateVerificationSummaryAttestation(opts *config.VsaCommandOptions, passed bool, entries []models.LogEntry) ([]byte, error) {
	var inputAttestations []*vpb.VerificationSummary_InputAttestation

	for _, entry := range entries {
		for _, e := range entry {
			entryUriPath, err := url.JoinPath(opts.RekorUrl, "api/v1/log/entries")
			if err != nil {
				return nil, err
			}

			body, err := sigstore.ParseInTotoBody(e)
			if err != nil {
				return nil, err
			}

			inputAttestations = append(inputAttestations, &vpb.VerificationSummary_InputAttestation{
				Uri: fmt.Sprintf(
					"%s?logIndex=%d",
					entryUriPath,
					e.LogIndex,
				),
				Digest: map[string]string{
					body.Spec.Content.PayloadHash.Algorithm: body.Spec.Content.PayloadHash.Value,
				},
			})
		}
	}

	predicate := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: opts.VerifierId,
		},
		TimeVerified: timestamppb.Now(),
		ResourceUri:  opts.ArtifactUri,
		Policy: &vpb.VerificationSummary_Policy{
			Uri: fmt.Sprintf("https://github.com/liatrio/gh-trusted-builds-policy/releases/download/%s/bundle.tar.gz", opts.PolicyVersion),
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult(passed),
		PolicyLevel:        "SLSA_LEVEL_3",
		DependencyLevels:   map[string]uint64{},
	}

	return protojson.Marshal(predicate)
}
