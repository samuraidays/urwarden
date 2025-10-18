package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for urwarden
type Config struct {
	// File paths
	BlocklistPath string

	// Scoring thresholds
	MaliciousThreshold  int
	SuspiciousThreshold int

	// Performance settings
	MaxLineLength int
	BufferSize    int

	// HTTP client settings
	HTTPTimeout     time.Duration
	MaxIdleConns    int
	IdleConnTimeout time.Duration

	// Logging
	Verbose bool
}

// Default returns a default configuration
func Default() *Config {
	return &Config{
		BlocklistPath:       "data/blocklist.txt",
		MaliciousThreshold:  70,
		SuspiciousThreshold: 30,
		MaxLineLength:       1024 * 1024,
		BufferSize:          64 * 1024,
		HTTPTimeout:         30 * time.Second,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		Verbose:             false,
	}
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	if val := os.Getenv("URWARDEN_BLOCKLIST_PATH"); val != "" {
		c.BlocklistPath = val
	}
	if val := os.Getenv("URWARDEN_MALICIOUS_THRESHOLD"); val != "" {
		if threshold, err := strconv.Atoi(val); err == nil {
			c.MaliciousThreshold = threshold
		}
	}
	if val := os.Getenv("URWARDEN_SUSPICIOUS_THRESHOLD"); val != "" {
		if threshold, err := strconv.Atoi(val); err == nil {
			c.SuspiciousThreshold = threshold
		}
	}
	if val := os.Getenv("URWARDEN_VERBOSE"); val != "" {
		if verbose, err := strconv.ParseBool(val); err == nil {
			c.Verbose = verbose
		}
	}
}
