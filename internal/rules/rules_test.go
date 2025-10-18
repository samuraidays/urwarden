package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samuraidays/urwarden/internal/model"
	"github.com/samuraidays/urwarden/internal/rules"
)

func tempBlocklist(t *testing.T, lines string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(p, []byte(lines), 0o644); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}
	return p
}

func TestBlocklistHit(t *testing.T) {
	bl := tempBlocklist(t, `
# comment
0.0.0.0 bad.example.com
malicious.test
`)
	n := model.NormalizedURL{Host: "bad.example.com", TLD: "com"}
	rs := rules.EvaluateAll(n, bl)

	found := false
	for _, r := range rs {
		if r.Rule == rules.RuleBlocklistHit && r.Detail == "bad.example.com" && r.Weight == rules.WeightBlocklistHit {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected blocklist_hit reason")
	}
}

func TestSuspiciousTLD(t *testing.T) {
	n := model.NormalizedURL{Host: "foo.shop", TLD: "shop"}
	rs := rules.EvaluateAll(n, "")
	ok := false
	for _, r := range rs {
		if r.Rule == rules.RuleSuspiciousTLD && r.Detail == "shop" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected suspicious_tld for .shop")
	}
}

func TestPathHasLoginLike(t *testing.T) {
	n := model.NormalizedURL{Path: "/user/login", Query: "next=%2Fhome"}
	rs := rules.EvaluateAll(n, "")
	ok := false
	for _, r := range rs {
		if r.Rule == rules.RulePathHasLoginLike {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected path_has_login_like")
	}
}

func TestNoBlocklistFileIsOK(t *testing.T) {
	n := model.NormalizedURL{Host: "none.example", TLD: "example"}
	rs := rules.EvaluateAll(n, "data/does-not-exist.txt")
	// 圧倒的に重要なのは「パニックしない」こと。ここでは理由が0個でもOK。
	if rs == nil {
		t.Fatalf("reasons should be empty slice, not nil")
	}
}

func TestBlocklist_SubdomainMatch(t *testing.T) {
	bl := tempBlocklist(t, `
example.com
`)
	n := model.NormalizedURL{Host: "sub.bad.example.com", TLD: "com"}
	rs := rules.EvaluateAll(n, bl)

	found := false
	for _, r := range rs {
		if r.Rule == rules.RuleBlocklistHit {
			if r.Weight != rules.WeightBlocklistHit {
				t.Fatalf("unexpected weight: %d", r.Weight)
			}
			// 完全一致ではないが、subdomain一致で当たる想定
			if !strings.Contains(r.Detail, "example.com") {
				t.Fatalf("detail must mention example.com: %s", r.Detail)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected blocklist_hit by subdomain match")
	}
}

func TestBlocklist_NoFalsePositive_SimilarSuffix(t *testing.T) {
	bl := tempBlocklist(t, `
example.com
`)
	n := model.NormalizedURL{Host: "reallybadexample.com", TLD: "com"}
	rs := rules.EvaluateAll(n, bl)

	for _, r := range rs {
		if r.Rule == rules.RuleBlocklistHit {
			t.Fatalf("should not match similar suffix without dot-boundary")
		}
	}
}

func TestBlocklist_ExactMatchStillWorks(t *testing.T) {
	bl := tempBlocklist(t, `
bad.example.com
`)
	n := model.NormalizedURL{Host: "bad.example.com", TLD: "com"}
	rs := rules.EvaluateAll(n, bl)
	found := false
	for _, r := range rs {
		if r.Rule == rules.RuleBlocklistHit && r.Detail != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected blocklist_hit (exact)")
	}
}
