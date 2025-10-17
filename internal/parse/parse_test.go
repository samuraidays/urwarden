package parse_test

import (
	"testing"

	"github.com/samuraidays/urwarden/internal/parse"
)

func TestNormalizeURL_OK(t *testing.T) {
	n, err := parse.NormalizeURL("https://Bad.Example.com/Login?next=%2Fhome")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n.Scheme != "https" {
		t.Errorf("scheme: got %s", n.Scheme)
	}
	if n.Host != "bad.example.com" {
		t.Errorf("host: got %s", n.Host)
	}
	if n.TLD != "com" {
		t.Errorf("tld: got %s", n.TLD)
	}
	if n.Path != "/Login" {
		t.Errorf("path: got %s", n.Path)
	}
	if n.Query != "next=%2Fhome" {
		t.Errorf("query: got %s", n.Query)
	}
}

func TestNormalizeURL_InvalidScheme(t *testing.T) {
	_, err := parse.NormalizeURL("ftp://example.com")
	if err == nil {
		t.Fatalf("expected error for invalid scheme")
	}
}

func TestNormalizeURL_NoHost(t *testing.T) {
	_, err := parse.NormalizeURL("https://")
	if err == nil {
		t.Fatalf("expected error for empty host")
	}
}
