package input_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samuraidays/urwarden/internal/config"
	"github.com/samuraidays/urwarden/internal/input"
)

func TestFromArgsOrInput_Args(t *testing.T) {
	cfg := config.Default()
	got, err := input.FromArgsOrInput([]string{"https://a", "https://b"}, "", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

func TestFromArgsOrInput_File(t *testing.T) {
	cfg := config.Default()
	dir := t.TempDir()
	p := filepath.Join(dir, "u.txt")
	_ = os.WriteFile(p, []byte("\n# cmt\nhttps://a\nhttps://a\nhttps://b\n"), 0o644)

	got, err := input.FromArgsOrInput(nil, p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // 重複除去
		t.Fatalf("want 2, got %d", len(got))
	}
}
