package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishedFailurePreservesCompleteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	syncErr := errors.New("injected directory sync failure")
	err := writeFileWithSync(path, []byte("complete"), 0600, false, true, func(string) error { return syncErr })
	var published *PublishedError
	if !errors.As(err, &published) || !errors.Is(err, syncErr) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "complete" {
		t.Fatal(string(data), err)
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Fatal("temporary file retained", files)
	}
}
