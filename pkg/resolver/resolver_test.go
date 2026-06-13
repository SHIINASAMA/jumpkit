package resolver

import (
	"reflect"
	"testing"
)

func TestParseDNSOutput_dig(t *testing.T) {
	output := `142.250.198.78
2607:f8b0:4002:80f::2004
not-an-ip
1.2.3.4`

	ips := ParseDNSOutput(output, "dig +short example.com")
	expected := []string{"142.250.198.78", "2607:f8b0:4002:80f::2004", "1.2.3.4"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("got %v, want %v", ips, expected)
	}
}

func TestParseDNSOutput_nslookup_single(t *testing.T) {
	output := `Server:		114.114.114.114
Address:	114.114.114.114#53

Non-authoritative answer:
Name:	example.com
Address: 93.184.216.34`

	ips := ParseDNSOutput(output, "nslookup example.com")
	expected := []string{"93.184.216.34"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("got %v, want %v", ips, expected)
	}
}

func TestParseDNSOutput_nslookup_plural(t *testing.T) {
	output := `Server:  ns1.mydns.com
Address:  204.127.202.4#53

Non-authoritative answer:
Name:    google.com
Addresses:  64.233.187.99, 72.14.207.99, 64.233.167.99`

	ips := ParseDNSOutput(output, "nslookup google.com")
	expected := []string{"64.233.187.99", "72.14.207.99", "64.233.167.99"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("got %v, want %v", ips, expected)
	}
}

func TestParseDNSOutput_getent(t *testing.T) {
	output := "127.0.0.1 localhost.localdomain localhost"

	ips := ParseDNSOutput(output, "getent hosts localhost")
	expected := []string{"127.0.0.1"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("got %v, want %v", ips, expected)
	}
}

func TestParseDNSOutput_empty(t *testing.T) {
	ips := ParseDNSOutput("", "dig +short example.com")
	if len(ips) != 0 {
		t.Errorf("expected empty, got %v", ips)
	}
}

func TestParseDNSOutput_no_match(t *testing.T) {
	output := `Server:		114.114.114.114
Address:	114.114.114.114#53
** server can't find noexist.example.com: NXDOMAIN`

	ips := ParseDNSOutput(output, "nslookup noexist.example.com")
	if len(ips) != 0 {
		t.Errorf("expected empty, got %v", ips)
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "'example.com'"},
		{"it's.test", "'it'\\''s.test'"},
		{"a b.com", "'a b.com'"},
	}
	for _, c := range cases {
		got := shellQuote(c.in)
		if got != c.want {
			t.Errorf("shellQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatDNSCommand(t *testing.T) {
	cmd := DNSCommand{Name: "dig", Args: []string{"+short", "{target}"}}
	got := FormatDNSCommand(cmd, "example.com")
	want := "dig +short 'example.com'"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIsIPAddress(t *testing.T) {
	if !isIPAddress("1.2.3.4") {
		t.Error("1.2.3.4 should be valid")
	}
	if !isIPAddress("::1") {
		t.Error("::1 should be valid")
	}
	if isIPAddress("not-an-ip") {
		t.Error("not-an-ip should be invalid")
	}
}
