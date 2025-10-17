package score

import "github.com/samuraidays/urwarden/internal/model"

// Aggregate sums weights from reasons and returns score + label.
func Aggregate(reasons []model.Reason) (int, string) {
	total := 0
	for _, r := range reasons {
		total += r.Weight
	}
	label := labelOf(total)
	return total, label
}

func labelOf(score int) string {
	switch {
	case score >= 70:
		return "malicious"
	case score >= 30:
		return "suspicious"
	default:
		return "benign"
	}
}
