package git

import (
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func OpenLocalRepository() (*git.Repository, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("error reading current directory: %v", err)
	}
	return git.PlainOpen(wd)
}

func LocalDevSha(sha string) *plumbing.Reference {
	return plumbing.NewReferenceFromStrings("refs/heads/main", sha)
}
