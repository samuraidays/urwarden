package blocklist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/utils"
)

// Blocklist represents a cached blocklist with fast lookup capabilities
type Blocklist struct {
	domains map[string]struct{}
	mu      sync.RWMutex
	path    string
}

// New creates a new blocklist instance
func New(path string) *Blocklist {
	return &Blocklist{
		domains: make(map[string]struct{}),
		path:    path,
	}
}

// Load loads the blocklist from the specified file
func (b *Blocklist) Load() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear existing domains
	b.domains = make(map[string]struct{})

	path := b.path
	if path == "" {
		path = "data/blocklist.txt"
	}

	logger.Debug("loading blocklist from: %s", path)

	// Open the file
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// File doesn't exist - this is not an error, just an empty blocklist
		logger.Debug("blocklist file not found: %s", path)
		return nil
	}
	defer func() {
		if err := f.Close(); err != nil {
			logger.Warn("failed to close blocklist file: %v", err)
		}
	}()

	// Read and parse the file
	scanner := bufio.NewScanner(f)
	lineCount := 0
	domainCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse domain from the line
		// Support both "0.0.0.0 domain.com" and "domain.com" formats
		fields := strings.Fields(line)
		var domain string
		if len(fields) == 1 {
			domain = fields[0]
		} else {
			domain = fields[len(fields)-1]
		}

		// Normalize the domain
		normalized := utils.NormalizeDomain(domain)
		if normalized == "" {
			continue
		}

		b.domains[normalized] = struct{}{}
		domainCount++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %w", err)
	}

	logger.Info("loaded %d domains from blocklist (%d lines processed)", domainCount, lineCount)
	return nil
}

// Contains checks if a domain is in the blocklist
func (b *Blocklist) Contains(host string) (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Normalize the host
	host = strings.ToLower(strings.Trim(host, "."))

	// Check for exact match
	if _, exists := b.domains[host]; exists {
		return true, host
	}

	// Check for subdomain matches
	for domain := range b.domains {
		if strings.HasSuffix(host, "."+domain) {
			return true, domain
		}
	}

	return false, ""
}

// Size returns the number of domains in the blocklist
func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains)
}

// Reload reloads the blocklist from the file
func (b *Blocklist) Reload() error {
	return b.Load()
}
