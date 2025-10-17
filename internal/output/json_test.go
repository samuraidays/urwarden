package output_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/samuraidays/urwarden/internal/model"
	"github.com/samuraidays/urwarden/internal/output"
)

func TestWriteResultJSON(t *testing.T) {
	// STDOUT を一時的に差し替えて JSON を検証
	old := os.Stdout
	defer func() { os.Stdout = old }()

	r, w, _ := os.Pipe()
	os.Stdout = w

	n := model.NormalizedURL{
		Scheme: "https",
		Host:   "bad.example.com",
		TLD:    "com",
		Path:   "/login",
		Query:  "next=%2Fhome",
	}
	reasons := []model.Reason{
		{Rule: "blocklist_hit", Weight: 70, Detail: "bad.example.com"},
	}
	err := output.WriteResultJSON("https://bad.example.com/login?next=%2Fhome", n, 70, "malicious", reasons)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Close writer and read
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe: %v", err)
	}
	var out bytes.Buffer
	_, _ = out.ReadFrom(r)

	// 最低限のキー存在をざっくりチェック（厳密な構造検証は別途でもOK）
	s := out.String()
	for _, key := range []string{`"input_url"`, `"normalized"`, `"score"`, `"label"`, `"reasons"`, `"timestamp"`} {
		if !bytes.Contains([]byte(s), []byte(key)) {
			t.Fatalf("missing key %s in json: %s", key, s)
		}
	}

	// タイムスタンプはUTC前提（雛形では time.Now().UTC()）
	_ = time.Now() // 呼び出し元と同時刻比較はしない（テストが壊れやすくなるため）
}
