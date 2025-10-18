package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/input"
	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/output"
	"github.com/samuraidays/urwarden/internal/parse"
	"github.com/samuraidays/urwarden/internal/rules"
	"github.com/samuraidays/urwarden/internal/score"
	"github.com/samuraidays/urwarden/internal/version"
)

const (
	exitOK       = 0 // Success
	exitInternal = 1 // Internal error (file I/O, unexpected exceptions)
	exitInput    = 2 // Input error (invalid URLs, etc.)
)

func main() {
	// Parse command line flags
	var (
		showVersion bool
		infile      string
		verbose     bool
		blocklist   string
	)
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
	flag.StringVar(&infile, "input", "", "path to file with URLs (one per line). Use '-' for stdin")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose logging")
	flag.StringVar(&blocklist, "blocklist", "data/blocklist.txt", "path to blocklist file")

	// Custom usage message
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  urwarden <URL> [<URL> ...] [--input file|-] [--version] [--verbose] [--blocklist path]")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  urwarden 'https://bad.example.com/login'")
		fmt.Fprintln(os.Stderr, "  urwarden --input urls.txt")
		fmt.Fprintln(os.Stderr, "  cat urls.txt | urwarden --input -")
		fmt.Fprintln(os.Stderr, "  urwarden --verbose --blocklist custom.txt example.com")
		fmt.Fprintln(os.Stderr, "Exit codes: 0=ok, 1=internal error, 2=input error")
	}

	flag.Parse()

	// Show version and exit
	if showVersion {
		fmt.Printf("urwarden %s (commit %s, date %s, build %s)\n",
			version.Version, version.Commit, version.BuildDate, version.BuildNumber)
		os.Exit(exitOK)
	}

	// Initialize configuration
	cfg := config.Default()
	cfg.BlocklistPath = blocklist
	cfg.Verbose = verbose
	cfg.LoadFromEnv()

	// Set up logging
	if cfg.Verbose {
		logger.Default.SetLevel(logger.LevelDebug)
	}

	logger.Info("starting urwarden v%s", version.Version)

	// Collect URLs from command line arguments or input file
	urls, err := input.FromArgsOrInput(flag.Args(), infile, cfg)
	if err != nil {
		logger.Error("failed to collect URLs: %v", err)
		os.Exit(exitInput)
	}

	if len(urls) == 0 {
		flag.Usage()
		os.Exit(exitInput)
	}

	logger.Info("processing %d URLs", len(urls))

	// Initialize rule evaluator
	evaluator, err := rules.NewEvaluator(cfg.BlocklistPath, cfg)
	if err != nil {
		logger.Error("failed to initialize rule evaluator: %v", err)
		os.Exit(exitInternal)
	}

	// Process each URL
	hadInputError := false
	processedCount := 0

	for _, inputURL := range urls {
		logger.Debug("processing URL: %s", inputURL)

		// Parse and normalize URL
		norm, err := parse.NormalizeURL(inputURL)
		if err != nil {
			logger.Warn("failed to normalize URL %s: %v", inputURL, err)
			hadInputError = true
			continue
		}

		// Evaluate rules
		reasons := evaluator.EvaluateAll(norm)

		// Calculate score and label
		total, label := score.Aggregate(reasons, cfg)

		// Output result as JSON
		if err := output.WriteResultJSON(inputURL, norm, total, label, reasons); err != nil {
			logger.Error("failed to write JSON output: %v", err)
			os.Exit(exitInternal)
		}

		processedCount++
	}

	logger.Info("processed %d URLs successfully", processedCount)

	// Exit with appropriate code
	if hadInputError {
		logger.Warn("some URLs could not be processed")
		os.Exit(exitInput)
	}

	os.Exit(exitOK)
}
