package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nullt3r/massmap/pkg/scanner"
)

func writeCacheFile(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
	return path
}

func TestGetTopDoesNotPanicWhenCountExceedsSize(t *testing.T) {
	tmp := t.TempDir()
	path := writeCacheFile(t, tmp, `{"80": 1}`)

	findings := []scanner.Finding{}
	pc := &Ports{Path: path, Findings: &findings}

	got, err := pc.GetTop(2)
	if err != nil {
		t.Fatalf("GetTop returned error: %v", err)
	}
	if len(got) != 1 || got[0] != "80" {
		t.Fatalf("GetTop(2) = %v, want [\"80\"]", got)
	}
}

func TestGetTopHandlesNonPositiveCount(t *testing.T) {
	tmp := t.TempDir()
	path := writeCacheFile(t, tmp, `{"80": 2, "22": 1}`)

	findings := []scanner.Finding{}
	pc := &Ports{Path: path, Findings: &findings}

	got, err := pc.GetTop(0)
	if err != nil {
		t.Fatalf("GetTop returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("GetTop(0) = %v, want []", got)
	}
}
