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

func Acquire(dir string) (*Lock, error) { return acquire(dir, "process.lock") }

// AcquireInstallation serializes setup independently of the daemon writer lock.
func AcquireInstallation(dir string) (*Lock, error) { return acquire(dir, "setup.lock") }
func acquire(dir, name string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
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
	return WriteFile(path, data, 0600, false)
}

// WriteFile publishes complete contents and permissions in one filesystem step.
// Exclusive publication uses a hard link, so a concurrent creator is preserved.
func WriteFile(path string, data []byte, mode os.FileMode, exclusive bool) error {
	return writeFile(path, data, mode, exclusive, true)
}

// WriteSnapshot atomically replaces disposable runtime data without fsync.
// Identity, credentials and recovery journals must use Write or WriteJSON.
func WriteSnapshot(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), 0600, false, false)
}

func writeFile(path string, data []byte, mode os.FileMode, exclusive, durable bool) error {
	return writeFileWithSync(path, data, mode, exclusive, durable, SyncDirectory)
}

// PublishedError means the complete file is visible, but crash durability has
// not been confirmed. Callers must preserve it instead of treating it as absent.
type PublishedError struct{ Err error }

func (e *PublishedError) Error() string {
	return "文件已发布，但目录同步失败：" + e.Err.Error()
}
func (e *PublishedError) Unwrap() error { return e.Err }

func SyncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeFileWithSync(path string, data []byte, mode os.FileMode, exclusive, durable bool, syncDirectory func(string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".derper-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if durable {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if exclusive {
		err = os.Link(f.Name(), path)
	} else {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	if !durable {
		return nil
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return &PublishedError{Err: err}
	}
	return nil
}

// Store owns a deployment's writer lock until all workers have stopped.
type Store struct {
	dir  string
	lock *Lock
}

func Open(dir string) (*Store, error) {
	l, err := Acquire(dir)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, lock: l}, nil
}
func (s *Store) Close() error { return s.lock.Close() }
func (s *Store) Dir() string  { return s.dir }
func (s *Store) LoadOrCreateIdentity() (key.NodePrivate, error) {
	return Identity(filepath.Join(s.dir, "identity.json"))
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
	data, err := fileio.ReadRegularFile(path, 16<<10)
	if err == nil {
		return DecodeIdentity(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return key.NodePrivate{}, err
	}
	cfg := struct{ PrivateKey key.NodePrivate }{}
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

// DecodeIdentity validates imported state without echoing key material.
func DecodeIdentity(data []byte) (key.NodePrivate, error) {
	var cfg struct{ PrivateKey key.NodePrivate }
	if json.Unmarshal(data, &cfg) != nil || cfg.PrivateKey.IsZero() {
		return key.NodePrivate{}, errors.New("DERP 身份文件无效或缺少私钥")
	}
	return cfg.PrivateKey, nil
}
