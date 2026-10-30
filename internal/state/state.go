// Package state owns process locks and crash-safe persistent state.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/gatework/derper-go/internal/fileio"
	"tailscale.com/types/key"
)

// Lock prevents concurrent writers across the daemon and administrative commands.
type Lock struct{ file *os.File }

func Acquire(dir string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "process.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("state lock must be a regular file")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state directory is in use: %w", err)
	}
	return &Lock{f}, nil
}

func (l *Lock) Close() error {
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return errors.Join(syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
}

func Write(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".derper-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return Write(path, append(b, '\n'))
}

// Identity preserves the upstream derper JSON representation, including its public identity.
func Identity(path string) (key.NodePrivate, error) {
	var cfg struct{ PrivateKey key.NodePrivate }
	data, err := fileio.ReadRegularFile(path, 16<<10)
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg.PrivateKey, fmt.Errorf("decode DERP identity: %w", err)
		}
		if cfg.PrivateKey.IsZero() {
			return cfg.PrivateKey, errors.New("DERP identity contains a zero key")
		}
		return cfg.PrivateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return cfg.PrivateKey, err
	}
	cfg.PrivateKey = key.NewNode()
	if err := WriteJSON(path, cfg); err != nil {
		return key.NodePrivate{}, err
	}
	return cfg.PrivateKey, nil
}

func NewOwner() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
