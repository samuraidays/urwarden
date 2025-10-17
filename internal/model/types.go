package model

import "time"

type NormalizedURL struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	TLD    string `json:"tld"`
	Path   string `json:"path"`
	Query  string `json:"query"`
}

type Reason struct {
	Rule   string `json:"rule"`   // blocklist_hit | suspicious_tld | path_has_login_like
	Weight int    `json:"weight"` // 70 | 20 | 10
	Detail string `json:"detail"` // matched value etc.
}

type Result struct {
	InputURL   string        `json:"input_url"`
	Normalized NormalizedURL `json:"normalized"`
	Score      int           `json:"score"`
	Label      string        `json:"label"` // benign | suspicious | malicious
	Reasons    []Reason      `json:"reasons"`
	Timestamp  time.Time     `json:"timestamp"`
}
