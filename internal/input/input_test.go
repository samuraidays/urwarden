package input_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samuraidays/urwarden/internal/input"
)

func TestFromArgsOrInput_Args(t *testing.T) {
	got, err := input.FromArgsOrInput([]string{"https://a", "https://b"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

func TestFromArgsOrInput_File(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "u.txt")
	_ = os.WriteFile(p, []byte("\n# cmt\nhttps://a\nhttps://a\nhttps://b\n"), 0o644)

	got, err := input.FromArgsOrInput(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // 重複除去
		t.Fatalf("want 2, got %d", len(got))
	}
}
