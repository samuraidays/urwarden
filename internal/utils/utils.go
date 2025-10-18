package utils

import (
	"strings"
)

// Dedupe removes duplicate strings from a slice while preserving order
func Dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// NormalizeDomain normalizes a domain name by converting to lowercase and trimming dots
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}

	// Remove comment fragments
	if i := strings.IndexByte(domain, '#'); i >= 0 {
		domain = strings.TrimSpace(domain[:i])
	}

	domain = strings.ToLower(strings.Trim(domain, "."))

	// Basic validation
	if domain == "" || strings.ContainsAny(domain, " /\\") {
		return ""
	}

	// Skip wildcards for now
	if strings.HasPrefix(domain, "*.") {
		return ""
	}

	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// ContainsAny checks if the string contains any of the specified substrings
func ContainsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// IsValidURLScheme checks if the scheme is valid (http or https)
func IsValidURLScheme(scheme string) bool {
	scheme = strings.ToLower(scheme)
	return scheme == "http" || scheme == "https"
}
