package rules

import (
	"strings"

	"github.com/samuraidays/urwarden/internal/blocklist"
	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/logger"
	"github.com/samuraidays/urwarden/internal/model"
)

const (
	// Rule names (used in JSON output)
	RuleBlocklistHit     = "blocklist_hit"       // Blocklist match
	RuleSuspiciousTLD    = "suspicious_tld"      // Suspicious TLD (domain suffix)
	RulePathHasLoginLike = "path_has_login_like" // URL path contains login-like keywords

	// Rule weights (score points)
	WeightBlocklistHit  = 70
	WeightSuspiciousTLD = 20
	WeightPathLoginLike = 10
)

// Suspicious TLDs that trigger a +20 score when found in URL suffixes
var suspiciousTLD = map[string]struct{}{
	"xyz": {}, "top": {}, "click": {}, "help": {}, "shop": {},
	"live": {}, "cam": {}, "kim": {}, "fit": {}, "country": {},
}

// Keywords that indicate login/phishing URLs when found in path+query
var loginLikeTokens = []string{
	"login", "signin", "verify", "update", "password", "passcode",
	"secure", "confirm", "invoice", "billing",
}

// Evaluator holds the rule evaluation state
type Evaluator struct {
	blocklist *blocklist.Blocklist
	config    *config.Config
}

// NewEvaluator creates a new rule evaluator
func NewEvaluator(blocklistPath string, cfg *config.Config) (*Evaluator, error) {
	bl := blocklist.New(blocklistPath)
	if err := bl.Load(); err != nil {
		return nil, err
	}

	return &Evaluator{
		blocklist: bl,
		config:    cfg,
	}, nil
}

// EvaluateAll evaluates all rules against the normalized URL
//
// Args:
//
//	n - normalized URL information (output from parse.NormalizeURL)
//
// Returns:
//
//	[]model.Reason - list of matching rules (empty slice if none)
func (e *Evaluator) EvaluateAll(n model.NormalizedURL) []model.Reason {
	reasons := make([]model.Reason, 0, 3)

	// Rule 1: blocklist_hit
	if hit, domain := e.blocklist.Contains(n.Host); hit {
		detail := domain
		if n.Host != domain && strings.HasSuffix(n.Host, "."+domain) {
			detail = "matched subdomain of " + domain
		}
		reasons = append(reasons, model.Reason{
			Rule:   RuleBlocklistHit,
			Weight: WeightBlocklistHit,
			Detail: detail,
		})
		logger.Debug("blocklist hit: %s -> %s", n.Host, domain)
	}

	// Rule 2: suspicious_tld
	if _, ok := suspiciousTLD[strings.ToLower(n.TLD)]; ok {
		reasons = append(reasons, model.Reason{
			Rule:   RuleSuspiciousTLD,
			Weight: WeightSuspiciousTLD,
			Detail: n.TLD,
		})
		logger.Debug("suspicious TLD: %s", n.TLD)
	}

	// Rule 3: path_has_login_like
	if matched := pathHasLoginLike(n.Path, n.Query); matched != "" {
		reasons = append(reasons, model.Reason{
			Rule:   RulePathHasLoginLike,
			Weight: WeightPathLoginLike,
			Detail: "matched: " + matched,
		})
		logger.Debug("login-like path: %s", matched)
	}

	return reasons
}

// pathHasLoginLike checks if path and query contain login-like keywords
func pathHasLoginLike(path, query string) string {
	// Combine path and query in lowercase
	s := strings.ToLower(path)
	if query != "" {
		s += "?" + strings.ToLower(query)
	}

	// Check for any login-like tokens
	for _, token := range loginLikeTokens {
		if strings.Contains(s, token) {
			return token
		}
	}
	return ""
}
