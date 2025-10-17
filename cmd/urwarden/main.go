package main

import (
	"fmt"
	"os"

	"github.com/samuraidays/urwarden/internal/output"
	"github.com/samuraidays/urwarden/internal/parse"
	"github.com/samuraidays/urwarden/internal/rules"
	"github.com/samuraidays/urwarden/internal/score"
)

const (
	exitOK       = 0
	exitInternal = 1
	exitInput    = 2
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: urwarden <URL>")
		os.Exit(exitInput)
	}
	inputURL := os.Args[1]

	// 1) Parse & Normalize
	norm, err := parse.NormalizeURL(inputURL)
	if err != nil {
		// input error (invalid scheme/host/URL)
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(exitInput)
	}

	// 2) Evaluate rules (missing data/blocklist.txt is OK)
	reasons := rules.EvaluateAll(norm, "data/blocklist.txt")

	// 3) Aggregate score + label
	total, label := score.Aggregate(reasons)

	// 4) Output JSON
	if err := output.WriteResultJSON(inputURL, norm, total, label, reasons); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write json:", err.Error())
		os.Exit(exitInternal)
	}

	os.Exit(exitOK)
}
