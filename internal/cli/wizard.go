package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gatework/derper-go/internal/config"
)

func wizard(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("wizard", flag.ContinueOnError)
	fs.SetOutput(errOut)
	c := config.Default()
	c.DNS.Mode = "manage"
	file := "./derper-server.json"
	force := false
	fs.StringVar(&c.Hostname, "hostname", "", "relay hostname")
	fs.StringVar(&c.ACME.Email, "email", "", "ACME contact email")
	fs.StringVar(&c.DNS.IPv4, "ipv4", "", "public IPv4 address")
	fs.StringVar(&c.Cloudflare.TokenFile, "token-file", "", "Cloudflare token file (not the token)")
	fs.StringVar(&file, "output", file, "configuration output file")
	fs.BoolVar(&c.ACME.AcceptTerms, "accept-terms", false, "accept the selected ACME CA terms")
	fs.BoolVar(&force, "force", false, "replace existing configuration")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	reader := bufio.NewReader(in)
	prompt := func(label string, p *string) error {
		if *p != "" {
			return nil
		}
		fmt.Fprint(out, label+": ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		*p = strings.TrimSpace(line)
		if *p == "" {
			return errors.New("value is required")
		}
		return nil
	}
	for _, item := range []struct {
		label string
		p     *string
	}{{"Hostname", &c.Hostname}, {"ACME email", &c.ACME.Email}, {"Public IPv4", &c.DNS.IPv4}, {"Cloudflare token file", &c.Cloudflare.TokenFile}} {
		if err := prompt(item.label, item.p); err != nil {
			fmt.Fprintln(errOut, err)
			return 2
		}
	}
	if !c.ACME.AcceptTerms {
		var answer string
		if err := prompt("Accept Let's Encrypt terms (yes/no)", &answer); err != nil || answer != "yes" {
			fmt.Fprintln(errOut, "ACME terms were not accepted")
			return 2
		}
		c.ACME.AcceptTerms = true
	}
	b, err := json.Marshal(c)
	if err == nil {
		c, err = config.Decode(b)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	b, err = json.MarshalIndent(c, "", "  ")
	if err == nil {
		err = writeExclusive(file, append(b, '\n'), force)
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintln(out, "created", file)
	return 0
}
