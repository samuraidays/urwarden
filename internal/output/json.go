package output

import (
	"encoding/json"
	"os"
	"time"

	"github.com/samuraidays/urwarden/internal/model"
)

// WriteResultJSON encodes the result as JSON to STDOUT.
func WriteResultJSON(inputURL string, norm model.NormalizedURL, score int, label string, reasons []model.Reason) error {
	res := model.Result{
		InputURL:   inputURL,
		Normalized: norm,
		Score:      score,
		Label:      label,
		Reasons:    reasons,
		Timestamp:  time.Now().UTC(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}
