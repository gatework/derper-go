package daemon

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gatework/derper-go/internal/config"
)

func TestDoctorChecksBothConfiguredAddressFamilies(t *testing.T) {
	s := config.Settings{IPv4: netip.MustParseAddr("192.0.2.1"), IPv6: netip.MustParseAddr("2001:db8::1")}
	ipv4 := net.IPAddr{IP: net.ParseIP("192.0.2.1")}
	ipv6 := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	if err := checkAddresses(s, []net.IPAddr{ipv4}); err == nil {
		t.Fatal("missing configured IPv6 accepted")
	}
	if err := checkAddresses(s, []net.IPAddr{ipv4, ipv6}); err != nil {
		t.Fatal(err)
	}
	if err := checkAddresses(s, []net.IPAddr{{IP: net.ParseIP("192.0.2.2")}, ipv6}); err == nil {
		t.Fatal("proxy exit mismatch accepted")
	}
	if err := checkAddresses(config.Settings{}, nil); err == nil {
		t.Fatal("empty DNS result accepted")
	}
}
