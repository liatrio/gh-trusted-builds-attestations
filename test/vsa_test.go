package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	assert "github.com/stretchr/testify/require"
)

func TestVsaCmd(t *testing.T) {
	t.Parallel()

	const (
		fakeAttestationPredicateType     = "https://liatr.io/attestations/integration-test/v1"
		testVerifierId                   = "integration-test-verifier"
		verificationSummaryPredicateType = "https://slsa.dev/verification_summary/v0.2"
	)

	signerIdentitiesQuery := "data.governance.local_signer_identities"
	if os.Getenv("CI") != "" {
		signerIdentitiesQuery = "data.governance.ci_signer_identities"
	}

	type fakePredicate struct {
		Value string
	}

	type attestationWrapper struct {
		logEntry *models.LogEntryAnon
		digest   gcrv1.Hash
	}

	signAttestation := func(t *testing.T, artifact *containerImage, payload []byte) *attestationWrapper {
		t.Helper()

		ctx := context.Background()
		signer, err := sign.SignerFromKeyOpts(ctx, "", "", options.KeyOpts{
			IDToken:   idToken,
			FulcioURL: fulcioUrl,
			RekorURL:  rekorUrl,
		})
		assert.NoError(t, err, "failed to create signer")
		defer signer.Close()

		publicKeyBytes, err := signer.Bytes(ctx)
		assert.NoError(t, err)

		wrapped := dsse.WrapSigner(signer, types.IntotoPayloadType)
		signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload))
		assert.NoError(t, err, "error signing message")

		rekorClient, err := rekor.GetRekorClient(rekorUrl)
		assert.NoError(t, err)

		logEntry, err := cosign.TLogUploadInTotoAttestation(ctx, rekorClient, signedPayload, publicKeyBytes)
		assert.NoError(t, err)

		opts := []static.Option{
			static.WithLayerMediaType(types.DssePayloadType),
			static.WithCertChain(signer.Cert, signer.Chain),
			static.WithBundle(cbundle.EntryToBundle(logEntry)),
		}

		attestation, err := static.NewAttestation(signedPayload, opts...)
		assert.NoError(t, err)

		digest, err := name.ParseReference(artifact.Name())
		assert.NoError(t, err)

		signedEntity, err := ociremote.SignedEntity(digest)
		assert.NoError(t, err)

		entityWithAttestation, err := mutate.AttachAttestationToEntity(signedEntity, attestation)
		assert.NoError(t, err)
		assert.NoError(t, ociremote.WriteAttestations(digest.Context(), entityWithAttestation))

		signatureDigest, err := attestation.Digest()
		assert.NoError(t, err)

		return &attestationWrapper{
			logEntry: logEntry,
			digest:   signatureDigest,
		}
	}

	makeFakeAttestation := func(t *testing.T, artifact *containerImage) *attestationWrapper {
		t.Helper()

		buffer := make([]byte, 4)
		_, err := rand.Read(buffer)
		assert.NoError(t, err)

		randomValue := hex.EncodeToString(buffer)

		stmnt := &in_toto.Statement{
			StatementHeader: in_toto.StatementHeader{
				Type:          in_toto.StatementInTotoV01,
				PredicateType: fakeAttestationPredicateType,
				Subject: []in_toto.Subject{
					{
						Name: artifact.name,
						Digest: common.DigestSet{
							artifact.digest.Algorithm: artifact.digest.Hex,
						},
					},
				},
			},
			Predicate: &fakePredicate{
				Value: randomValue,
			},
		}

		payload, err := json.Marshal(stmnt)
		assert.NoError(t, err, "error marshalling attestation")

		return signAttestation(t, artifact, payload)
	}

	type verificationInputAttestation struct {
		Digest common.DigestSet `json:"digest"`
		Uri    string           `json:"uri"`
	}

	type verificationSummaryPredicate struct {
		InputAttestations []verificationInputAttestation `json:"input_attestations"`
		Policy            struct {
			Uri string `json:"uri"`
		} `json:"policy"`
		PolicyLevel        string    `json:"policy_level"`
		ResourceUri        string    `json:"resource_uri"`
		TimeVerified       time.Time `json:"time_verified"`
		VerificationResult string    `json:"verification_result"`
		Verifier           struct {
			Id string `json:"id"`
		} `json:"verifier"`
	}

	type verificationSummaryAttestation struct {
		PredicateType string
		Subject       []in_toto.Subject
		Predicate     *verificationSummaryPredicate
	}

	type testCase struct {
		name string
		int
		flags       []string
		assert      func(t *testing.T, artifact *containerImage, inputAttestations []*attestationWrapper, vsa verificationSummaryAttestation)
		expectedErr string
	}

	testCases := []*testCase{
		{
			name: "image passes local policy bundle",
			flags: []string{
				"--policy-url",
				"./fixtures/rego/governance",
				"--verifier-id",
				testVerifierId,
				"--signer-identities-query",
				signerIdentitiesQuery,
				"--policy-query",
				"data.governance.always_allow",
			},
			assert: func(t *testing.T, artifact *containerImage, inputs []*attestationWrapper, vsa verificationSummaryAttestation) {
				assert.Len(t, vsa.Subject, 1, "expected a single subject")
				assert.Equal(t, in_toto.Subject{
					Name: artifact.name,
					Digest: common.DigestSet{
						artifact.digest.Algorithm: artifact.digest.Hex,
					},
				}, vsa.Subject[0])

				assert.Len(t, vsa.Predicate.InputAttestations, len(inputs))
				for _, inputAttestation := range inputs {
					var actualInput *verificationInputAttestation
					for _, input := range vsa.Predicate.InputAttestations {
						actualDigest, ok := input.Digest[inputAttestation.digest.Algorithm]
						if ok && actualDigest == inputAttestation.digest.Hex {
							actualInput = &input
							break
						}
					}

					assert.NotNil(t, actualInput)
					expectedLogEntryUri := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", rekorUrl, *inputAttestation.logEntry.LogIndex)
					assert.Equal(t, expectedLogEntryUri, actualInput.Uri)
				}
				assert.Equal(t, "./fixtures/rego/governance", vsa.Predicate.Policy.Uri)
				assert.Equal(t, "SLSA_LEVEL_3", vsa.Predicate.PolicyLevel)
				assert.Equal(t, artifact.name, vsa.Predicate.ResourceUri)
				assert.WithinDurationf(t, time.Now(), vsa.Predicate.TimeVerified, time.Minute, "expected attestation to be recent")
				assert.Equal(t, "PASSED", vsa.Predicate.VerificationResult)
				assert.Equal(t, testVerifierId, vsa.Predicate.Verifier.Id)
			},
		},
		{
			name: "image fails local policy bundle",
			flags: []string{
				"--policy-url",
				"./fixtures/rego/governance",
				"--verifier-id",
				testVerifierId,
				"--signer-identities-query",
				signerIdentitiesQuery,
				"--policy-query",
				"data.governance.always_deny",
			},
			assert: func(t *testing.T, artifact *containerImage, inputs []*attestationWrapper, vsa verificationSummaryAttestation) {
				assert.Equal(t, "FAILED", vsa.Predicate.VerificationResult)
			},
		},
		{
			name: "policy is missing signer identities",
			flags: []string{
				"--policy-url",
				"./fixtures/rego/governance",
				"--verifier-id",
				testVerifierId,
				"--signer-identities-query",
				"data.invalid",
				"--policy-query",
				"data.governance.always_allow",
			},
			expectedErr: "missing signer identities",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			artifact, err := randomImage()
			assert.NoError(t, err, "error making random image")
			inputAttestation := makeFakeAttestation(t, artifact)

			flags := append(makeGlobalFlags(artifact.digest.String()), tc.flags...)
			vsaCmd := &cmd.VSA{}
			err = vsaCmd.Init(ctx, flags)
			assert.NoError(t, err)

			err = vsaCmd.Run()
			fmt.Println("expected", tc.expectedErr)
			if tc.expectedErr != "" {
				fmt.Println("wtf??", tc.expectedErr)
				fmt.Println(err)
				assert.ErrorContains(t, err, tc.expectedErr)
				return
			}
			assert.NoError(t, err)

			signatures, err := verifyImageAttestations(ctx, artifact)
			assert.NoError(t, err)

			allAttestations, err := filterAttestations[verificationSummaryAttestation](signatures, verificationSummaryPredicateType)
			assert.NoError(t, err)

			assert.Len(t, allAttestations, 1, "expected a single VSA")
			tc.assert(t, artifact, []*attestationWrapper{inputAttestation}, allAttestations[0])
		})
	}

	t.Run("image with multiple input attestations", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		var inputs []*attestationWrapper
		for i := 0; i <= 2; i++ {
			inputs = append(inputs, makeFakeAttestation(t, artifact))
		}

		flags := append(makeGlobalFlags(artifact.digest.String()),
			"--policy-url",
			"./fixtures/rego/governance",
			"--verifier-id",
			testVerifierId,
			"--signer-identities-query",
			signerIdentitiesQuery,
			"--policy-query",
			"data.governance.always_allow",
		)

		vsaCmd := &cmd.VSA{}
		err = vsaCmd.Init(ctx, flags)
		assert.NoError(t, err)
		err = vsaCmd.Run()
		assert.NoError(t, err)

		signatures, err := verifyImageAttestations(ctx, artifact)
		assert.NoError(t, err)

		allAttestations, err := filterAttestations[verificationSummaryAttestation](signatures, verificationSummaryPredicateType)
		assert.NoError(t, err)
		assert.Len(t, allAttestations, 1)
		vsa := allAttestations[0]

		assert.Len(t, vsa.Predicate.InputAttestations, len(inputs))
		for _, inputAttestation := range inputs {
			var actualInput *verificationInputAttestation
			for _, input := range vsa.Predicate.InputAttestations {
				actualDigest, ok := input.Digest[inputAttestation.digest.Algorithm]

				if ok && actualDigest == inputAttestation.digest.Hex {
					actualInput = &input
					break
				}
			}

			assert.NotNil(t, actualInput)
			expectedLogEntryUri := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%d", rekorUrl, *inputAttestation.logEntry.LogIndex)
			assert.Equal(t, expectedLogEntryUri, actualInput.Uri)
		}
	})

	t.Run("image has no attestations", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		flags := append(makeGlobalFlags(artifact.digest.String()),
			"--policy-url",
			"./fixtures/rego/governance",
			"--verifier-id",
			testVerifierId,
			"--signer-identities-query",
			signerIdentitiesQuery,
			"--policy-query",
			"data.governance.always_allow",
		)

		vsaCmd := &cmd.VSA{}
		err = vsaCmd.Init(ctx, flags)
		assert.NoError(t, err)

		err = vsaCmd.Run()
		assert.ErrorContains(t, err, "no matching attestations")
	})
}
