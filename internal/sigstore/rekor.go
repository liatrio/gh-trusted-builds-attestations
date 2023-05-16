package sigstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/liatrio/gh-trusted-builds-attestations/internal/util"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type InTotoBody struct {
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Content struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
			PayloadHash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"payloadHash"`
		} `json:"content"`
		PublicKey string `json:"publicKey"`
	} `json:"spec"`
}

func ParseInTotoBody(e models.LogEntryAnon) (*InTotoBody, error) {
	dec, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	var body *InTotoBody
	err = json.Unmarshal(dec, &body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func SearchByHash(ctx context.Context, hash, rekorUrl string) ([]string, error) {
	client, err := rekor.GetRekorClient(rekorUrl)
	if err != nil {
		return nil, err
	}
	results, err := client.Index.SearchIndex(&index.SearchIndexParams{
		Query:   &models.SearchIndex{Hash: hash},
		Context: ctx,
	})
	if err != nil {
		return nil, err
	}

	return results.GetPayload(), nil
}

func RetrieveEntriesByUUID(ctx context.Context, uuids []string, rekorUrl string) ([]models.LogEntry, error) {
	client, err := rekor.GetRekorClient(rekorUrl)
	if err != nil {
		return nil, err
	}

	uuidChunks := util.SplitList(uuids, 10)
	var logEntries []models.LogEntry

	for _, chunk := range uuidChunks {
		results, err := client.Entries.SearchLogQuery(&entries.SearchLogQueryParams{
			Entry:   &models.SearchLogQuery{EntryUUIDs: chunk},
			Context: ctx,
		})
		if err != nil {
			return nil, err
		}

		logEntries = append(logEntries, results.GetPayload()...)
	}

	return logEntries, nil
}
