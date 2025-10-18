package score

import (
	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/model"
)

// This package handles score calculation and label determination.
// It aggregates weights from various rules (blocklist, TLD, path, etc.)
// and classifies URLs as "benign", "suspicious", or "malicious" based on the total score.

// Aggregate calculates the total score from reasons and determines the appropriate label
//
// Returns:
//   - int: total score (e.g., 80)
//   - string: label string ("benign" / "suspicious" / "malicious")
func Aggregate(reasons []model.Reason, cfg *config.Config) (int, string) {
	total := 0

	// Sum up all the weights from the detected rules
	// Example: [{rule:blocklist_hit, weight:70}, {rule:path_has_login_like, weight:10}]
	for _, r := range reasons {
		total += r.Weight
		logger.Debug("added %d points for rule %s: %s", r.Weight, r.Rule, r.Detail)
	}

	// Determine label based on score thresholds
	label := labelOf(total, cfg)

	logger.Debug("total score: %d, label: %s", total, label)
	return total, label
}

// labelOf determines the appropriate label based on the score and configuration
//
// Score thresholds:
//   - >= malicious_threshold → "malicious"
//   - >= suspicious_threshold → "suspicious"
//   - < suspicious_threshold → "benign"
func labelOf(score int, cfg *config.Config) string {
	switch {
	case score >= cfg.MaliciousThreshold:
		return "malicious"
	case score >= cfg.SuspiciousThreshold:
		return "suspicious"
	default:
		return "benign"
	}
}
