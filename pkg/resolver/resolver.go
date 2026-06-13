package resolver

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type DNSCommand struct {
	Name string
	Args []string
}

func GetAvailableDNSCommand() (DNSCommand, error) {
	commands := []DNSCommand{
		{Name: "dig", Args: []string{"+short", "{target}"}},
		{Name: "nslookup", Args: []string{"{target}"}},
		{Name: "getent", Args: []string{"hosts", "{target}"}},
	}
	for _, cmd := range commands {
		if isCommandAvailable(cmd.Name) {
			return cmd, nil
		}
	}
	return DNSCommand{}, fmt.Errorf("no DNS command available (tried dig, nslookup, getent)")
}

func FormatDNSCommand(cmd DNSCommand, target string) string {
	quoted := shellQuote(target)
	args := make([]string, len(cmd.Args))
	for i, arg := range cmd.Args {
		args[i] = strings.ReplaceAll(arg, "{target}", quoted)
	}
	return fmt.Sprintf("%s %s", cmd.Name, strings.Join(args, " "))
}

func ParseDNSOutput(output, command string) []string {
	lines := strings.Split(output, "\n")
	var ips []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(command, "dig") {
			if isIPAddress(line) {
				ips = append(ips, line)
			}
			continue
		}

		if strings.HasPrefix(command, "nslookup") {
			if strings.HasPrefix(line, "Addresses:") || strings.HasPrefix(line, "Address:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					for _, chunk := range strings.Split(parts[1], ",") {
						addr := strings.TrimSpace(chunk)
						if isIPAddress(addr) {
							ips = append(ips, addr)
						}
					}
				}
			}
			continue
		}

		if strings.HasPrefix(command, "getent") {
			parts := strings.Fields(line)
			if len(parts) >= 1 && isIPAddress(parts[0]) {
				ips = append(ips, parts[0])
			}
			continue
		}
	}

	return ips
}

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

func isCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
