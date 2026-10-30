package fileio

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBoundedRegularInputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFile(path, 4); err == nil {
		t.Fatal("oversized input accepted")
	}
	fifo := path + ".fifo"
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadRegularFile(fifo, 8<<10); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		f, _ := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if f != nil {
			f.Close()
		}
		t.Fatal("FIFO blocked file reader")
	}
}
