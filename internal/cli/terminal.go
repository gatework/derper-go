package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Poll the caller-owned terminal instead of abandoning blocked reader goroutines.
func readByte(ctx context.Context, in io.Reader) (byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if file, ok := in.(*os.File); ok {
		poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		for {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			n, err := unix.Poll(poll, 100)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return 0, err
			}
			if n > 0 {
				break
			}
		}
	}
	var b [1]byte
	_, err := io.ReadFull(in, b[:])
	return b[0], err
}
func readLine(ctx context.Context, in io.Reader) (string, error) {
	var b []byte
	for len(b) <= 8192 {
		value, err := readByte(ctx, in)
		if err != nil {
			return "", err
		}
		if value == '\n' {
			return strings.TrimSpace(string(b)), nil
		}
		b = append(b, value)
	}
	return "", errors.New("输入过长")
}
func readSecret(ctx context.Context, in *os.File) (string, error) {
	saved, err := term.MakeRaw(int(in.Fd()))
	if err != nil {
		return "", err
	}
	defer term.Restore(int(in.Fd()), saved)
	var b []byte
	for len(b) <= 8192 {
		value, err := readByte(ctx, in)
		if err != nil {
			return "", err
		}
		switch value {
		case 3:
			return "", context.Canceled
		case 4:
			return "", io.EOF
		case '\r', '\n':
			return string(b), nil
		case 8, 127:
			if len(b) > 0 {
				_, n := utf8.DecodeLastRune(b)
				b = b[:len(b)-n]
			}
		default:
			b = append(b, value)
		}
	}
	return "", errors.New("凭据输入过长")
}
