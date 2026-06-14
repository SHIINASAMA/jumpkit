package core

import (
	"fmt"
	"strings"
)

type AuthType string

const (
	AuthTypePrivateKey AuthType = "private-key"
	AuthTypePassword   AuthType = "passwd"
)

type HopConfig struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	User           string   `json:"user,omitempty"`
	AuthType       AuthType `json:"auth_type,omitempty"`
	AuthToken      string   `json:"-"`
	UseInternalDns bool     `json:"use_internal_dns"`
}

type SSHAction int

const (
	ActionConnect SSHAction = iota
	ActionTunnel
)

type SSHCommand struct {
	Command    string
	Display    string
	Action     SSHAction
	TunnelPort int
}

type HopResult struct {
	HopConfig HopConfig
	Command   string
	Output    string
	IPs       []string
	Err       error
}

type AnalysisResult struct {
	Hops          []HopConfig
	Results       []HopResult
	FirstResolved *HopResult
	TargetIP      string
	SSHCommands   []SSHCommand
	Summary       string
}

func (h HopConfig) String() string {
	if h.User != "" {
		return fmt.Sprintf("%s@%s", h.User, h.Host)
	}
	return h.Host
}

func (c SSHCommand) String() string {
	if c.Display != "" {
		return c.Display
	}
	return c.Command
}

func (r *AnalysisResult) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "=== JumpKit Analysis Result ===\n\n")
	fmt.Fprintf(&sb, "Chain:\n")
	for i, hop := range r.Hops {
		prefix := "  "
		if i > 0 {
			prefix = "  → "
		}
		fmt.Fprintf(&sb, "%s%s\n", prefix, hop)
	}

	fmt.Fprintf(&sb, "\nDNS Resolution Results:\n")
	for _, res := range r.Results {
		status := "✗ failed"
		if res.Err != nil {
			status = fmt.Sprintf("✗ error: %s", res.Err)
		} else if len(res.IPs) > 0 {
			status = fmt.Sprintf("✓ %s", strings.Join(res.IPs, ", "))
		}
		fmt.Fprintf(&sb, "  [%s] %s\n", res.HopConfig.Host, status)
		fmt.Fprintf(&sb, "    cmd: %s\n", res.Command)
		if res.Output != "" {
			for _, line := range strings.Split(res.Output, "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(&sb, "    out: %s\n", line)
				}
			}
		}
	}

	if r.FirstResolved != nil {
		fmt.Fprintf(&sb, "\n✓ First resolved at hop: %s\n", r.FirstResolved.HopConfig.Host)
		fmt.Fprintf(&sb, "  Target IP: %s\n", r.TargetIP)
	}

	if len(r.SSHCommands) > 0 {
		fmt.Fprintf(&sb, "\nRecommended SSH Commands:\n")
		for _, cmd := range r.SSHCommands {
			fmt.Fprintf(&sb, "  %s\n", cmd)
		}
	}

	fmt.Fprintf(&sb, "\nSummary: %s\n", r.Summary)
	return sb.String()
}
