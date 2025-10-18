package parse

import (
	"errors"
	"net/url"
	"strings"

	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/model"
	"github.com/samuraidays/urwarden/internal/utils"
)

// This package handles URL parsing and normalization.
// It takes a URL string and breaks it down into scheme/host/tld/path/query
// components, returning a model.NormalizedURL struct.

// ErrInvalidScheme is returned when an unsupported URL scheme is detected
var ErrInvalidScheme = errors.New("invalid scheme: only http/https are allowed")

// ErrNoHost is returned when the hostname is empty
var ErrNoHost = errors.New("invalid url: host is empty")

// NormalizeURL parses a URL string and returns a normalized URL struct.
// Only http and https schemes are allowed.
// Returns: NormalizedURL struct on success, error on failure.
func NormalizeURL(input string) (model.NormalizedURL, error) {
	logger.Debug("normalizing URL: %s", input)

	// Use Go's standard url.Parse to break down the URL
	u, err := url.Parse(input)
	if err != nil {
		logger.Debug("failed to parse URL: %v", err)
		return model.NormalizedURL{}, err
	}

	// Normalize scheme to lowercase
	scheme := strings.ToLower(u.Scheme)

	// Only allow http and https schemes
	if !utils.IsValidURLScheme(scheme) {
		logger.Debug("invalid scheme: %s", scheme)
		return model.NormalizedURL{}, ErrInvalidScheme
	}

	// Normalize hostname to lowercase and trim dots
	host := strings.ToLower(strings.Trim(u.Hostname(), "."))

	// Hostname cannot be empty
	if host == "" {
		logger.Debug("empty hostname")
		return model.NormalizedURL{}, ErrNoHost
	}

	// Extract TLD (simple rule: everything after the last dot)
	tld := host
	if i := strings.LastIndex(host, "."); i >= 0 && i+1 < len(host) {
		tld = host[i+1:]
	}

	// Get path and query components
	path := u.EscapedPath()
	query := u.RawQuery

	result := model.NormalizedURL{
		Scheme: scheme,
		Host:   host,
		TLD:    tld,
		Path:   path,
		Query:  query,
	}

	logger.Debug("normalized URL: %+v", result)
	return result, nil
}
