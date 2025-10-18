package score_test

import (
	"testing"

	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/model"
	"github.com/samuraidays/urwarden/internal/score"
)

func TestLabelBoundaries(t *testing.T) {
	cfg := config.Default()
	cases := []struct {
		total int
		want  string
	}{
		{29, "benign"},
		{30, "suspicious"},
		{69, "suspicious"},
		{70, "malicious"},
	}
	for _, c := range cases {
		got := scoreLabel(c.total, cfg)
		if got != c.want {
			t.Errorf("score %d => label %s, want %s", c.total, got, c.want)
		}
	}
}

func scoreLabel(total int, cfg *config.Config) string {
	_, label := score.Aggregate([]model.Reason{{Weight: total}}, cfg)
	return label
}
