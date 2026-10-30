package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityPersistsAndNeverReplacesCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derper.key")
	a, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Identity(path)
	if err != nil || a.Public() != b.Public() {
		t.Fatal("identity changed")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private identity permissions")
	}
	if err = os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Identity(path); err == nil {
		t.Fatal("corrupt identity replaced")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "broken" {
		t.Fatal("identity was overwritten")
	}
}
func TestExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if b, err := Acquire(dir); err == nil {
		b.Close()
		t.Fatal("second writer admitted")
	}
	a.Close()
	b, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}
func TestLockRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("untouched"), 0600)
	os.Symlink(target, filepath.Join(dir, "process.lock"))
	if l, err := Acquire(dir); err == nil {
		l.Close()
		t.Fatal("followed lock symlink")
	}
}
