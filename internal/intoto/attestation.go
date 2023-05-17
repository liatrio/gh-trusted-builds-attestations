package intoto

import (
	"fmt"
	"net/url"

	spb "github.com/in-toto/attestation/go/v1"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/sigstore"
	"github.com/sigstore/rekor/pkg/generated/models"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v0"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func verificationResult(passed bool) string {
	if passed {
		return "PASSED"
	}

	return "FAILED"
}

func CreateVerificationSummaryAttestation(opts *config.VsaCommandOptions, passed bool, entries []models.LogEntry) (*spb.Statement, error) {
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

	predicateJson, err := protojson.Marshal(predicate)
	if err != nil {
		return nil, err
	}
	predicateStruct := &structpb.Struct{}
	err = protojson.Unmarshal(predicateJson, predicateStruct)
	if err != nil {
		return nil, err
	}

	statement := &spb.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []*spb.Statement_Subject{{
			Name: opts.ArtifactUri,
			Digest: map[string]string{
				opts.ArtifactDigest.Type: opts.ArtifactDigest.RawDigest,
			},
		}},
		PredicateType: "https://slsa.dev/verification_summary/v0.2",
		Predicate:     predicateStruct,
	}

	return statement, nil
}
