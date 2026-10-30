package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gatework/derper-go/internal/cli"
)

func main() { os.Exit(run()) }
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}
