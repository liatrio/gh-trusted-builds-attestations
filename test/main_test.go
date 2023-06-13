package test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	gcrrandom "github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/blob"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/tuf"
)

const (
	imageRepo = "liatrio/pr-attestation-fixtures"
)

var (
	sigstoreConfigDir = ".sigstore"
	backupConfigDir   = ".sigstore-backup"

	githubToken = getEnv("GITHUB_TOKEN", "")
	idToken     = getEnv("ID_TOKEN", "")
	fulcioUrl   = getEnv("FULCIO_URL", "http://fulcio.fulcio-system.svc:8080")
	rekorUrl    = getEnv("REKOR_URL", "http://rekor.rekor-system.svc:8080")
	tufRoot     = getEnv("TUF_ROOT", "root.json")
	tufMirror   = getEnv("TUF_MIRROR", "http://tuf.tuf-system.svc:8080")
	registryUrl = getEnv("REGISTRY_URL", "registry.local:5001")

	expectedKeylessIssuer  = getEnv("KEYLESS_ISSUER", "https://kubernetes.default.svc.cluster.local")
	expectedKeylessSubject = getEnv("KEYLESS_SUBJECT", "https://kubernetes.io/namespaces/default/serviceaccounts/default")
)

type containerImage struct {
	name   string
	digest gcrv1.Hash
}

func (c *containerImage) Name() string {
	return c.name + "@" + c.digest.String()
}

func TestMain(m *testing.M) {
	if tufRoot == "" {
		log.Fatalln("must specify TUF root file")
	}

	for _, setting := range []string{fulcioUrl, rekorUrl, tufMirror, registryUrl} {
		if !validUrl(setting) {
			log.Fatalln("invalid URL:", setting)
		}
	}

	if err := saveTufRoot(); err != nil {
		log.Fatalln("error stashing existing TUF root", err)
	}

	rootJson, err := blob.LoadFileOrURL(tufRoot)
	if err != nil {
		log.Fatalln("error loading TUF root", err)
	}

	if err = tuf.Initialize(context.Background(), tufMirror, rootJson); err != nil {
		log.Fatalln("error initializing TUF root", err)
	}

	var exitCode int
	defer func() {
		if err := restoreTufRoot(); err != nil {
			log.Fatalln("error restoring TUF root", err)
		}

		os.Exit(exitCode)
	}()

	exitCode = m.Run()
}

func validUrl(value string) bool {
	if value == "" {
		return false
	}

	_, err := url.ParseRequestURI(value)

	return err == nil
}

func saveTufRoot() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sigstoreDir := filepath.Join(homeDir, sigstoreConfigDir)
	backupDir := filepath.Join(homeDir, backupConfigDir)

	if fileExists(backupDir) {
		if err = os.RemoveAll(backupDir); err != nil {
			return err
		}
	}

	// if the Sigstore config directory doesn't exist, we're using the root baked into cosign, so there's nothing to persist
	if !fileExists(sigstoreDir) {
		return nil
	}

	return os.Rename(sigstoreDir, backupDir)
}

func restoreTufRoot() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sigstoreDir := filepath.Join(homeDir, sigstoreConfigDir)
	backupDir := filepath.Join(homeDir, backupConfigDir)

	if err = os.RemoveAll(sigstoreDir); err != nil {
		return err
	}

	if !fileExists(backupDir) {
		return nil
	}

	return os.Rename(backupDir, sigstoreDir)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	return true
}

func getEnv(varName, defaultValue string) string {
	value := os.Getenv(varName)
	if value == "" {
		return defaultValue
	}

	return value
}

func makeGlobalFlags(artifactDigest string) []string {
	artifactUri := testImageName()
	return []string{
		"--fulcio-url",
		fulcioUrl,
		"--rekor-url",
		rekorUrl,
		"--artifact-digest",
		artifactDigest,
		"--artifact-uri",
		artifactUri,
		"--id-token",
		idToken,
	}
}

func testImageName() string {
	return fmt.Sprintf("%s/%s", registryUrl, imageRepo)
}

func randomImage() (*containerImage, error) {
	// create a random tag to avoid race conditions when running tests in parallel
	buffer := make([]byte, 4)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}

	randomTag := hex.EncodeToString(buffer)
	ref, err := name.ParseReference(testImageName() + ":" + randomTag)
	if err != nil {
		return nil, err
	}

	img, err := gcrrandom.Image(512, 2)
	if err != nil {
		return nil, err
	}

	if err = remote.Write(ref, img); err != nil {
		return nil, err
	}

	remoteImage, err := remote.Get(ref)
	if err != nil {
		return nil, err
	}

	return &containerImage{
		name:   testImageName(),
		digest: remoteImage.Digest,
	}, nil
}

func cosignCheckOpts(ctx context.Context) (*cosign.CheckOpts, error) {
	fulcioRoots, err := fulcioroots.Get()
	if err != nil {
		return nil, err
	}
	fulcioIntermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, err
	}

	ctLogKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		return nil, err
	}

	rekorKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, err
	}

	rekorClient, err := rekor.GetRekorClient(rekorUrl)
	if err != nil {
		return nil, err
	}

	return &cosign.CheckOpts{
		ClaimVerifier:     cosign.IntotoSubjectClaimVerifier,
		RekorClient:       rekorClient,
		RekorPubKeys:      rekorKeys,
		RootCerts:         fulcioRoots,
		IntermediateCerts: fulcioIntermediates,
		CTLogPubKeys:      ctLogKeys,
		Identities: []cosign.Identity{
			{
				Issuer:  expectedKeylessIssuer,
				Subject: expectedKeylessSubject,
			},
		},
	}, nil
}

func verifyImageAttestations(ctx context.Context, image *containerImage) ([]oci.Signature, error) {
	imageRef, err := name.ParseReference(image.Name())
	if err != nil {
		return nil, err
	}

	opts, err := cosignCheckOpts(ctx)
	if err != nil {
		return nil, err
	}

	signatures, bundleVerified, err := cosign.VerifyImageAttestations(ctx, imageRef, opts)
	if err != nil {
		return nil, err
	}

	if !bundleVerified {
		return nil, fmt.Errorf("failed to verify attestations")
	}

	return signatures, nil
}

func filterAttestations[T any](signatures []oci.Signature, predicateType string) ([]T, error) {
	attestations := make([]T, 0)

	for _, sig := range signatures {
		payload, err := sig.Payload()
		if err != nil {
			return nil, fmt.Errorf("error examining signature payload: %s", err)
		}

		var intotoWrapper map[string]any
		if err = json.Unmarshal(payload, &intotoWrapper); err != nil {
			return nil, fmt.Errorf("error unmarshalling attestation: %s", err)
		}

		attestation, ok := intotoWrapper["payload"]
		if !ok {
			return nil, fmt.Errorf("expected payload field to contain attestation")
		}

		attJson, err := base64.StdEncoding.DecodeString(attestation.(string))
		if err != nil {
			return nil, fmt.Errorf("error decoding attestation: %s", err)
		}

		var unstructuredAtt map[string]any
		if err = json.Unmarshal(attJson, &unstructuredAtt); err != nil {
			return nil, fmt.Errorf("error unmarshalling attestation: %s", err)
		}

		if unstructuredAtt["predicateType"] != predicateType {
			continue
		}

		var att T
		if err = json.Unmarshal(attJson, &att); err != nil {
			return nil, fmt.Errorf("error unmarshalling attestation into provided type: %s", err)
		}

		attestations = append(attestations, att)
	}

	return attestations, nil
}
