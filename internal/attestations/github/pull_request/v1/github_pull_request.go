package v1

import (
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

const (
	PredicateType = "https://liatr.io/attestations/github-pull-request/v1"
)

type Subject struct {
	RepositoryLink string
	CommitSha      string
}

type Reviewer struct {
	Name       string    `json:"name"`
	Approved   bool      `json:"approved"`
	ReviewLink string    `json:"reviewLink"`
	Timestamp  time.Time `json:"timestamp"`
}

type Contributor struct {
	Name string `json:"name,omitempty"`
}

type Predicate struct {
	Link               string         `json:"link"`
	Title              string         `json:"title"`
	Author             string         `json:"author"`
	MergedBy           string         `json:"mergedBy"`
	CreatedAt          time.Time      `json:"createdAt"`
	MergedAt           time.Time      `json:"mergedAt"`
	Base               string         `json:"base"`
	Head               string         `json:"head"`
	Approved           bool           `json:"approved"`
	Reviewers          []*Reviewer    `json:"reviewers"`
	Contributors       []*Contributor `json:"contributors"`
	PredicateCreatedAt time.Time      `json:"predicateCreatedAt"`
}

func Attestation(s *Subject, p *Predicate) *in_toto.Statement {
	return &in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: PredicateType,
			Subject: []in_toto.Subject{
				{
					Name: s.RepositoryLink,
					Digest: common.DigestSet{
						"sha1": s.CommitSha,
					},
				},
			},
		},
		Predicate: p,
	}
}
