package intoto

import (
	"fmt"
	"net/url"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v0"
	spb "github.com/in-toto/attestation/go/v1"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func verificationResult(passed bool) string {
	if passed {
		return "PASSED"
	}

	return "FAILED"
}

type Attestation struct {
	Attestation     string
	RekorLogIndex   int64
	DigestAlgorithm string
	DigestHex       string
}

type PolicyEvaluationResult struct {
	Allow        bool
	Attestations []*Attestation
}

func CreateVerificationSummaryAttestation(opts *config.VsaCommandOptions, result *PolicyEvaluationResult) ([]byte, error) {
	var inputAttestations []*vpb.VerificationSummary_InputAttestation

	for _, attestation := range result.Attestations {
		entryUriPath, err := url.JoinPath(opts.RekorUrl, "api/v1/log/entries")
		if err != nil {
			return nil, err
		}

		inputAttestations = append(inputAttestations, &vpb.VerificationSummary_InputAttestation{
			Uri: fmt.Sprintf(
				"%s?logIndex=%d",
				entryUriPath,
				attestation.RekorLogIndex,
			),
			Digest: map[string]string{
				attestation.DigestAlgorithm: attestation.DigestHex,
			},
		})
	}

	predicate := &vpb.VerificationSummary{
		Verifier: &vpb.VerificationSummary_Verifier{
			Id: opts.VerifierId,
		},
		TimeVerified: timestamppb.Now(),
		ResourceUri:  opts.ArtifactUri,
		Policy: &vpb.VerificationSummary_Policy{
			Uri: opts.PolicyUrl.String(),
		},
		InputAttestations:  inputAttestations,
		VerificationResult: verificationResult(result.Allow),
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

	return protojson.Marshal(statement)
}
