package main

import (
	"fmt"
	"os"

	"github.com/liatrio/gh-trusted-builds-attestations/cmd"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
