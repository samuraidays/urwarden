package parse

import (
	"errors"
	"net/url"
	"strings"

	"github.com/samuraidays/urwarden/internal/model"
)

var ErrInvalidScheme = errors.New("invalid scheme: only http/https are allowed")
var ErrNoHost = errors.New("invalid url: host is empty")

// NormalizeURL parses and normalizes the input URL according to v0.1 rules.
func NormalizeURL(input string) (model.NormalizedURL, error) {
	u, err := url.Parse(input)
	if err != nil {
		return model.NormalizedURL{}, err
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return model.NormalizedURL{}, ErrInvalidScheme
	}

	host := strings.ToLower(strings.Trim(u.Hostname(), "."))
	if host == "" {
		return model.NormalizedURL{}, ErrNoHost
	}

	// v0.1: naive TLD = last label after final dot
	tld := host
	if i := strings.LastIndex(host, "."); i >= 0 && i+1 < len(host) {
		tld = host[i+1:]
	}

	path := u.EscapedPath()
	query := u.RawQuery

	return model.NormalizedURL{
		Scheme: scheme,
		Host:   host,
		TLD:    tld,
		Path:   path,
		Query:  query,
	}, nil
}
