// Package cli contains the testable command boundary. Library packages never exit.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/gatework/derper-go/internal/app"
	"github.com/gatework/derper-go/internal/certmgr"
	"github.com/gatework/derper-go/internal/config"
	"github.com/gatework/derper-go/internal/state"
)

var Version = "dev"
var Commit = "unknown"

const help = `Usage: derper-go <command> [options]

Commands:
  server          Run the DERP/STUN relay and automatic maintenance
  check           Validate configuration and local TLS files, without network or writes
  wizard          Generate a configuration interactively or using flags
  doctor          Query DNS, TLS, STUN and local tailscaled health
  dns plan|apply  Inspect or reconcile address records
  cert status|import|renew
                  Inspect, import or renew an offline certificate cache
  export-derpmap  Export policy fragment or raw DERPMap JSON
  service render|install
                  Render or install a systemd unit (install does not start it)
  version         Show application and upstream versions

Use --help on a command for its options.
Configuration defaults to ./derper-server.json. Select one with -c or --config.
`

func Run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(out, help)
		return 0
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, help)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) > 1 {
			fmt.Fprintln(errOut, "version takes no arguments")
			return 2
		}
		upstream := "v1.104.4"
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, d := range info.Deps {
				if d.Path == "tailscale.com" {
					upstream = d.Version
				}
			}
		}
		fmt.Fprintf(out, "derper-go %s (%s), tailscale.com %s\n", Version, Commit, upstream)
		return 0
	}
	if args[0] == "wizard" {
		return wizard(args[1:], in, out, errOut)
	}
	command := args[0]
	rest := args[1:]
	sub := ""
	if command == "dns" || command == "cert" || command == "service" {
		if len(rest) == 1 && (rest[0] == "--help" || rest[0] == "-h") {
			fmt.Fprint(out, help)
			return 0
		}
		if len(rest) == 0 {
			fmt.Fprint(errOut, help)
			return 2
		}
		sub = rest[0]
		rest = rest[1:]
	}
	valid := map[string]bool{"server": true, "check": true, "doctor": true, "export-derpmap": true, "dns/plan": true, "dns/apply": true, "cert/status": true, "cert/import": true, "cert/renew": true, "service/render": true, "service/install": true}
	name := command
	if sub != "" {
		name += "/" + sub
	}
	if !valid[name] {
		fmt.Fprintf(errOut, "unknown command %q\n", name)
		return 2
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := "./derper-server.json"
	fs.StringVar(&path, "config", path, "configuration file")
	fs.StringVar(&path, "c", path, "configuration file")
	format, certPath, keyPath, binary := "policy", "", "", "/usr/local/bin/derper-go"
	var adopt []string
	force := false
	switch name {
	case "export-derpmap":
		fs.StringVar(&format, "format", format, "policy or derpmap")
	case "dns/apply":
		fs.Func("adopt-record-id", "explicitly adopt a matching existing record (repeat for A/AAAA)", func(s string) error { adopt = append(adopt, s); return nil })
	case "cert/import":
		fs.StringVar(&certPath, "certificate", "", "PEM certificate chain to import")
		fs.StringVar(&keyPath, "private-key", "", "PEM private key to import")
	case "cert/renew":
		fs.BoolVar(&force, "force", false, "renew before the renewal window; still respects CA Retry-After")
	case "service/render", "service/install":
		fs.StringVar(&binary, "binary", binary, "installed executable path")
		if name == "service/install" {
			fs.BoolVar(&force, "force", false, "replace an existing managed unit")
		}
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "unexpected positional arguments")
		return 2
	}
	c, err := config.Load(path)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(errOut, &slog.HandlerOptions{Level: logLevel(c.LogLevel)}))
	encode := func(v any) error { e := json.NewEncoder(out); e.SetIndent("", "  "); return e.Encode(v) }
	lockRun := func(action func() error) error {
		l, err := state.Acquire(c.StateDir)
		if err != nil {
			return err
		}
		defer l.Close()
		return action()
	}
	switch name {
	case "server":
		err = app.Run(ctx, c, logger)
	case "check":
		err = app.Check(c)
		if err == nil {
			fmt.Fprintln(out, "configuration valid")
		}
	case "doctor":
		probe, cancel := context.WithTimeout(ctx, 30*time.Second)
		results := app.Doctor(probe, c)
		cancel()
		err = encode(results)
		if err == nil {
			for _, r := range results {
				if !r.OK {
					err = errors.New("one or more health checks failed")
					break
				}
			}
		}
	case "export-derpmap":
		var b []byte
		b, err = app.Export(c, format)
		if err == nil {
			_, err = out.Write(b)
		}
	case "dns/plan", "dns/apply":
		if c.DNS.Mode == "off" {
			err = errors.New("DNS is disabled")
			break
		}
		request, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		controller := app.DNS(c)
		if sub == "plan" {
			changes, e := controller.Plan(request)
			err = e
			if err == nil {
				err = encode(changes)
			}
		} else {
			err = lockRun(func() error {
				changes, e := controller.Apply(request, adopt...)
				if e != nil {
					return e
				}
				return encode(changes)
			})
		}
	case "cert/status":
		if c.TLS.Mode == "manual" {
			get, e := certmgr.Manual(c.Hostname, c.TLS.Certificate, c.TLS.PrivateKey)
			err = e
			if err == nil {
				pair, e := get(nil)
				err = e
				if err == nil {
					err = encode(certmgr.CertificateStatus(pair.Leaf, c.Hostname))
				}
			}
		} else {
			status, e := certmgr.CachedStatus(c.CertificateConfig())
			err = e
			if err == nil {
				err = encode(status)
			}
		}
	case "cert/import":
		if c.TLS.Mode != "acme" {
			err = errors.New("cert import requires tls.mode=acme")
			break
		}
		if certPath == "" || keyPath == "" {
			err = errors.New("--certificate and --private-key are required")
			break
		}
		err = lockRun(func() error { return certmgr.Import(c.CertificateConfig(), certPath, keyPath) })
	case "cert/renew":
		if c.TLS.Mode != "acme" {
			err = errors.New("cert renew requires tls.mode=acme")
			break
		}
		err = lockRun(func() error { return certmgr.Renew(ctx, c.CertificateConfig(), force) })
	case "service/render", "service/install":
		var unit string
		unit, err = renderUnit(binary, path, c)
		if err == nil {
			if sub == "render" {
				_, err = io.WriteString(out, unit)
			} else {
				err = installUnit(ctx, unit, force)
				if err == nil {
					fmt.Fprintln(out, "installed derper-go.service; enable and start it when ready")
				}
			}
		}
	}
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return 0
		}
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func logLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WriteExclusive avoids silently replacing operator-maintained configuration.
func writeExclusive(path string, b []byte, force bool) error {
	if force {
		return state.Write(path, b)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}
