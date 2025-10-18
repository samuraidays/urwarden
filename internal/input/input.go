package input

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/utils"
)

// FromArgsOrInput reads URLs from either command line arguments or input file/STDIN
// - path == "" uses command line arguments
// - path == "-" reads from STDIN
// - otherwise reads from the specified file
// Empty lines and lines starting with # are skipped
func FromArgsOrInput(args []string, path string, cfg *config.Config) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		// Use command line arguments directly
		// Example: urwarden https://a https://b
		return utils.Dedupe(args), nil
	}

	var r io.ReadCloser
	if path == "-" {
		// Read from STDIN
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		r = f
		defer func() {
			if err := r.Close(); err != nil {
				logger.Warn("failed to close file: %v", err)
			}
		}()
	}

	sc := bufio.NewScanner(r)
	// Expand buffer for long lines
	buf := make([]byte, 0, cfg.BufferSize)
	sc.Buffer(buf, cfg.MaxLineLength)

	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	logger.Debug("read %d URLs from input", len(out))
	return utils.Dedupe(out), nil
}
