package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

	makePolicyBundle := func(t *testing.T) string {
		t.Helper()

		tmpDir, err := os.MkdirTemp(os.TempDir(), "remote-policy-bundle-*")
		assert.NoError(t, err)

		bundleFileName := filepath.Join(tmpDir, "bundle.tar.gz")
		bundleTgz, err := os.Create(bundleFileName)
		assert.NoError(t, err)
		defer bundleTgz.Close()

		gzipWriter := gzip.NewWriter(bundleTgz)

		defer gzipWriter.Close()

		tarWriter := tar.NewWriter(gzipWriter)
		defer tarWriter.Close()

		governanceDir := filepath.Join("fixtures", "rego", "governance")
		entries, err := os.ReadDir(governanceDir)
		assert.NoError(t, err)

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			file, err := os.Open(filepath.Join(governanceDir, entry.Name()))
			assert.NoError(t, err)

			fileStat, err := file.Stat()
			assert.NoError(t, err)

			header, err := tar.FileInfoHeader(fileStat, fileStat.Name())
			assert.NoError(t, err)

			header.Name = filepath.Join("governance", fileStat.Name())

			assert.NoError(t, tarWriter.WriteHeader(header))

			_, err = io.Copy(tarWriter, file)
			assert.NoError(t, err)
		}

		return bundleFileName
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

	findInputAttestationByDigest := func(vsa verificationSummaryAttestation, expectedInput *attestationWrapper) *verificationInputAttestation {
		for _, input := range vsa.Predicate.InputAttestations {
			actualDigest, ok := input.Digest[expectedInput.digest.Algorithm]
			if ok && actualDigest == expectedInput.digest.Hex {
				return &input
			}
		}

		return nil
	}

	type testCase struct {
		name string
		int
		flags           []string
		assert          func(t *testing.T, artifact *containerImage, inputAttestations []*attestationWrapper, vsa verificationSummaryAttestation)
		expectedInitErr string
		expectedRunErr  string
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
					actualInput := findInputAttestationByDigest(vsa, inputAttestation)
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
			expectedRunErr: "missing signer identities",
		},
		{
			name: "invalid policy url",
			flags: []string{
				"--policy-url",
				"oci://policy.bundle",
				"--verifier-id",
				testVerifierId,
				"--signer-identities-query",
				signerIdentitiesQuery,
				"--policy-query",
				"data.governance.always_allow",
			},
			expectedInitErr: "unsupported scheme provided",
		},
		{
			name: "no policy url flag",
			flags: []string{
				"--verifier-id",
				testVerifierId,
				"--signer-identities-query",
				signerIdentitiesQuery,
				"--policy-query",
				"data.governance.always_allow",
			},
			expectedInitErr: "policy-url must be provided",
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
			if tc.expectedInitErr != "" {
				assert.ErrorContains(t, err, tc.expectedInitErr)
				return
			}
			assert.NoError(t, err)

			err = vsaCmd.Run()
			if tc.expectedRunErr != "" {
				assert.ErrorContains(t, err, tc.expectedRunErr)
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
			actualInput := findInputAttestationByDigest(vsa, inputAttestation)
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

	t.Run("remote policy bundle", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		policyBundle := makePolicyBundle(t)
		fmt.Println("policy bundle", policyBundle)

		lis, err := net.Listen("tcp", ":0")
		assert.NoError(t, err)
		fileServer := http.FileServer(http.Dir(filepath.Dir(policyBundle)))
		mux := http.NewServeMux()
		mux.Handle("/", fileServer)

		s := &http.Server{
			Addr:    ":0",
			Handler: mux,
		}

		go func() {
			err := s.Serve(lis)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Log("http serve error:", err)
			}
		}()

		defer func() {
			assert.NoError(t, s.Shutdown(ctx))
		}()

		artifact, err := randomImage()
		assert.NoError(t, err, "error making random image")

		_ = makeFakeAttestation(t, artifact)

		fsPort := lis.Addr().(*net.TCPAddr).Port
		remotePolicyBundleUri := fmt.Sprintf("http://localhost:%d/bundle.tar.gz", fsPort)

		flags := append(makeGlobalFlags(artifact.digest.String()),
			"--policy-url",
			remotePolicyBundleUri,
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
		assert.NoError(t, vsaCmd.Run())

		signatures, err := verifyImageAttestations(ctx, artifact)
		assert.NoError(t, err)

		allAttestations, err := filterAttestations[verificationSummaryAttestation](signatures, verificationSummaryPredicateType)
		assert.NoError(t, err)

		assert.Len(t, allAttestations, 1, "expected a single VSA")
		vsa := allAttestations[0]
		assert.Equal(t, remotePolicyBundleUri, vsa.Predicate.Policy.Uri)
	})
}
