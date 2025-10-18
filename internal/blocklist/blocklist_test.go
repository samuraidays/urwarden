package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlocklist(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	blocklistFile := filepath.Join(tmpDir, "test_blocklist.txt")

	// Write test data to the file
	testData := `# Test blocklist
0.0.0.0 bad.example.com
malicious.test
127.0.0.1 another.bad.com
# This is a comment
good.example.com
`
	if err := os.WriteFile(blocklistFile, []byte(testData), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create blocklist and load it
	bl := New(blocklistFile)
	if err := bl.Load(); err != nil {
		t.Fatalf("failed to load blocklist: %v", err)
	}

	// Test exact matches
	tests := []struct {
		host     string
		expected bool
		domain   string
	}{
		{"bad.example.com", true, "bad.example.com"},
		{"malicious.test", true, "malicious.test"},
		{"another.bad.com", true, "another.bad.com"},
		{"good.example.com", true, "good.example.com"},
		{"safe.example.com", false, ""},
		{"nonexistent.com", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			contains, domain := bl.Contains(tt.host)
			if contains != tt.expected {
				t.Errorf("Contains(%q) = %v, want %v", tt.host, contains, tt.expected)
			}
			if domain != tt.domain {
				t.Errorf("Contains(%q) domain = %q, want %q", tt.host, domain, tt.domain)
			}
		})
	}

	// Test subdomain matches
	subdomainTests := []struct {
		host     string
		expected bool
		domain   string
	}{
		{"sub.bad.example.com", true, "bad.example.com"},
		{"www.malicious.test", true, "malicious.test"},
		{"sub.another.bad.com", true, "another.bad.com"},
		{"sub.safe.example.com", false, ""},
	}

	for _, tt := range subdomainTests {
		t.Run(tt.host, func(t *testing.T) {
			contains, domain := bl.Contains(tt.host)
			if contains != tt.expected {
				t.Errorf("Contains(%q) = %v, want %v", tt.host, contains, tt.expected)
			}
			if domain != tt.domain {
				t.Errorf("Contains(%q) domain = %q, want %q", tt.host, domain, tt.domain)
			}
		})
	}

	// Test size
	expectedSize := 4 // bad.example.com, malicious.test, another.bad.com, good.example.com
	if size := bl.Size(); size != expectedSize {
		t.Errorf("Size() = %d, want %d", size, expectedSize)
	}
}

func TestBlocklistEmptyFile(t *testing.T) {
	// Test with empty file
	tmpDir := t.TempDir()
	blocklistFile := filepath.Join(tmpDir, "empty_blocklist.txt")

	bl := New(blocklistFile)
	if err := bl.Load(); err != nil {
		t.Fatalf("failed to load empty blocklist: %v", err)
	}

	if size := bl.Size(); size != 0 {
		t.Errorf("Size() = %d, want 0", size)
	}

	contains, _ := bl.Contains("any.domain.com")
	if contains {
		t.Errorf("Contains() = true, want false for empty blocklist")
	}
}

func TestBlocklistNonexistentFile(t *testing.T) {
	// Test with nonexistent file
	bl := New("nonexistent_file.txt")
	if err := bl.Load(); err != nil {
		t.Fatalf("failed to load nonexistent blocklist: %v", err)
	}

	if size := bl.Size(); size != 0 {
		t.Errorf("Size() = %d, want 0", size)
	}
}
