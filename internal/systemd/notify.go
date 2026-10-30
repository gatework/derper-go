// Package systemd owns integration with derper-go.service only.
package systemd

import (
	"net"
	"os"
	"strings"
	"time"
)

func Notify(message string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err = c.Write([]byte(message))
	return err
}
