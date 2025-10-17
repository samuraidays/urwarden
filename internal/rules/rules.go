package rules

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/samuraidays/urwarden/internal/model"
)

const (
	RuleBlocklistHit     = "blocklist_hit"
	RuleSuspiciousTLD    = "suspicious_tld"
	RulePathHasLoginLike = "path_has_login_like"

	WeightBlocklistHit  = 70
	WeightSuspiciousTLD = 20
	WeightPathLoginLike = 10
)

// v0.1 固定リスト（要件定義より）
var suspiciousTLD = map[string]struct{}{
	"xyz": {}, "top": {}, "click": {}, "help": {}, "shop": {},
	"live": {}, "cam": {}, "kim": {}, "fit": {}, "country": {},
}

// v0.1 固定語句（path + query の小文字部分一致）
var loginLikeTokens = []string{
	"login", "signin", "verify", "update", "password", "passcode",
	"secure", "confirm", "invoice", "billing",
}

// EvaluateAll runs the 3 rules and returns matched reasons.
//
// blocklistPath: typically "data/blocklist.txt" (missing file is OK)
func EvaluateAll(n model.NormalizedURL, blocklistPath string) []model.Reason {
	reasons := make([]model.Reason, 0, 3)

	// Rule 1: blocklist_hit
	if hit := blocklistHit(n.Host, blocklistPath); hit != "" {
		reasons = append(reasons, model.Reason{
			Rule:   RuleBlocklistHit,
			Weight: WeightBlocklistHit,
			Detail: hit,
		})
	}

	// Rule 2: suspicious_tld
	if _, ok := suspiciousTLD[strings.ToLower(n.TLD)]; ok {
		reasons = append(reasons, model.Reason{
			Rule:   RuleSuspiciousTLD,
			Weight: WeightSuspiciousTLD,
			Detail: n.TLD,
		})
	}

	// Rule 3: path_has_login_like
	if matched := pathHasLoginLike(n.Path, n.Query); matched != "" {
		reasons = append(reasons, model.Reason{
			Rule:   RulePathHasLoginLike,
			Weight: WeightPathLoginLike,
			Detail: "matched: " + matched,
		})
	}

	return reasons
}

// --- impl ---

func blocklistHit(host string, blocklistPath string) string {
	path := blocklistPath
	if path == "" {
		path = "data/blocklist.txt"
	}
	// Allow relative path from current working directory.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// Missing file is OK in v0.1 (no panic, no reason)
		return ""
	}
	defer func() {
		if err := f.Close(); err != nil {
			// v0.1ではログ出力なしで無視してOK（lint対策）
			_ = err
		}
	}()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// support "0.0.0.0 bad.example.com" or "bad.example.com"
		fields := strings.Fields(line)
		var dom string
		if len(fields) == 1 {
			dom = fields[0]
		} else {
			dom = fields[len(fields)-1]
		}
		dom = strings.ToLower(strings.Trim(dom, "."))
		if dom == host {
			return dom
		}
	}
	// ignore scanner error in v0.1
	return ""
}

func pathHasLoginLike(path, query string) string {
	s := strings.ToLower(path)
	if query != "" {
		s += "?" + strings.ToLower(query)
	}
	for _, t := range loginLikeTokens {
		if strings.Contains(s, t) {
			return t
		}
	}
	return ""
}
