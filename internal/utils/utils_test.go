package utils

import "testing"

func TestDedupe(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Dedupe(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Dedupe() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("Dedupe()[%d] = %v, want %v", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal domain",
			input:    "Example.COM",
			expected: "example.com",
		},
		{
			name:     "domain with trailing dot",
			input:    "example.com.",
			expected: "example.com",
		},
		{
			name:     "domain with comment",
			input:    "example.com # comment",
			expected: "example.com",
		},
		{
			name:     "wildcard domain",
			input:    "*.example.com",
			expected: "",
		},
		{
			name:     "invalid characters",
			input:    "example.com/path",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only spaces",
			input:    "   ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		substrings []string
		expected   bool
	}{
		{
			name:       "contains one",
			s:          "hello world",
			substrings: []string{"world", "foo"},
			expected:   true,
		},
		{
			name:       "contains none",
			s:          "hello world",
			substrings: []string{"foo", "bar"},
			expected:   false,
		},
		{
			name:       "empty substrings",
			s:          "hello world",
			substrings: []string{},
			expected:   false,
		},
		{
			name:       "empty string",
			s:          "",
			substrings: []string{"hello"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsAny(tt.s, tt.substrings)
			if result != tt.expected {
				t.Errorf("ContainsAny(%q, %v) = %v, want %v", tt.s, tt.substrings, result, tt.expected)
			}
		})
	}
}

func TestIsValidURLScheme(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		expected bool
	}{
		{"http", "http", true},
		{"https", "https", true},
		{"HTTP", "HTTP", true},
		{"HTTPS", "HTTPS", true},
		{"ftp", "ftp", false},
		{"file", "file", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURLScheme(tt.scheme)
			if result != tt.expected {
				t.Errorf("IsValidURLScheme(%q) = %v, want %v", tt.scheme, result, tt.expected)
			}
		})
	}
}
