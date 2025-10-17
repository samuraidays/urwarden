package score_test

import (
	"testing"

	"github.com/samuraidays/urwarden/internal/model"
	"github.com/samuraidays/urwarden/internal/score"
)

func TestLabelBoundaries(t *testing.T) {
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
		got := scoreLabel(c.total)
		if got != c.want {
			t.Errorf("score %d => label %s, want %s", c.total, got, c.want)
		}
	}
}

func scoreLabel(total int) string {
	_, label := score.Aggregate([]model.Reason{{Weight: total}})
	return label
}
