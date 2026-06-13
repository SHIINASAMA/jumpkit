package analyzer

import (
	"fmt"
	"strings"

	"jumpkit/pkg/core"
	"jumpkit/pkg/executor"
	"jumpkit/pkg/logger"
	"jumpkit/pkg/resolver"
)

type Analyzer struct {
	log *logger.Logger
}

func New(log *logger.Logger) *Analyzer {
	return &Analyzer{
		log: log,
	}
}

func (a *Analyzer) Analyze(hops []core.HopConfig) *core.AnalysisResult {
	if len(hops) == 0 {
		return &core.AnalysisResult{Summary: "no hops provided"}
	}

	dnsCmd, err := resolver.GetAvailableDNSCommand()
	if err != nil {
		a.log.Error("%v", err)
		return &core.AnalysisResult{
			Hops:    hops,
			Summary: fmt.Sprintf("DNS resolution unavailable: %v", err),
		}
	}

	targetDomain := hops[len(hops)-1].Host

	result := &core.AnalysisResult{
		Hops: hops,
	}

	var jumpChain []string
	resolved := false

	for i, hop := range hops {
		sshTarget := formatSSHTarget(hop, false)
		chainEntry := formatSSHTarget(hop, true)

		opts := buildJumpOptions(jumpChain)
		opts = append(opts, portArg(hop.Port)...)
		opts = append(opts, "-o", "StrictHostKeyChecking=no", "-o", "ForwardAgent=yes")
		exec := &executor.SSHExecutor{
			SSHOptions: opts,
			AuthType:   hop.AuthType,
			AuthToken:  hop.AuthToken,
		}

		hopResult := core.HopResult{HopConfig: hop}

		if resolved {
			out, err := exec.Execute(sshTarget, "echo ok")
			hopResult.Output = out
			hopResult.Err = err
			hopResult.Command = "echo ok"
			if err != nil {
				a.log.Step(i+1, len(hops), "%s ✗", hop.Host)
				a.log.Print("    %s", err)
			} else {
				a.log.Step(i+1, len(hops), "%s ✓", hop.Host)
			}
		} else {
			cmd := resolver.FormatDNSCommand(dnsCmd, targetDomain)
			hopResult.Command = cmd
			out, err := exec.Execute(sshTarget, cmd)
			hopResult.Output = out
			hopResult.Err = err

			if err != nil {
				a.log.Step(i+1, len(hops), "%s ✗", hop.Host)
				a.log.Print("    %s", err)
			} else {
				a.log.Step(i+1, len(hops), "%s ✓", hop.Host)
				ips := resolver.ParseDNSOutput(out, cmd)
				hopResult.IPs = ips
				if len(ips) > 0 {
					a.log.Print("    dns %s → %s", targetDomain, strings.Join(ips, ", "))
					if result.FirstResolved == nil {
						first := hopResult
						result.FirstResolved = &first
						result.TargetIP = hopResult.IPs[0]
						resolved = true
					}
				}
			}
		}

		result.Results = append(result.Results, hopResult)
		jumpChain = append(jumpChain, chainEntry)
	}

	result.SSHCommands = generateSSHCommands(hops, result)
	result.Summary = generateSummary(hops, result)

	for _, cmd := range result.SSHCommands {
		a.log.Print("")
		a.log.Print("%s", cmd.Command)
	}

	return result
}

func buildJumpOptions(jumpChain []string) []string {
	if len(jumpChain) == 0 {
		return nil
	}
	return []string{"-J", strings.Join(jumpChain, ",")}
}

func formatSSHTarget(hop core.HopConfig, withPort bool) string {
	var target string
	if hop.User != "" {
		target = fmt.Sprintf("%s@%s", hop.User, hop.Host)
	} else {
		target = hop.Host
	}
	if withPort {
		port := hop.Port
		if port == 0 {
			port = 22
		}
		target = fmt.Sprintf("%s:%d", target, port)
	}
	return target
}

func portArg(port int) []string {
	if port != 0 && port != 22 {
		return []string{"-p", fmt.Sprintf("%d", port)}
	}
	return nil
}

func generateSSHCommands(hops []core.HopConfig, result *core.AnalysisResult) []core.SSHCommand {
	if len(hops) < 2 {
		return nil
	}

	var commands []core.SSHCommand

	targetHop := hops[len(hops)-1]
	if targetHop.User == "" {
		targetHop.User = "admin"
	}

	var jumpHosts []string
	for i := 0; i < len(hops)-1; i++ {
		jumpHosts = append(jumpHosts, formatSSHTarget(hops[i], true))
	}

	targetAddr := targetHop.Host
	if result.TargetIP != "" {
		targetAddr = result.TargetIP
	}

	var args []string
	if len(jumpHosts) > 0 {
		args = append(args, "-J", strings.Join(jumpHosts, ","))
	}
	port := targetHop.Port
	if port == 0 {
		port = 22
	}
	args = append(args, "-p", fmt.Sprintf("%d", port))
	args = append(args, fmt.Sprintf("%s@%s", targetHop.User, targetAddr))

	cmd := fmt.Sprintf("ssh %s", strings.Join(args, " "))
	commands = append(commands, core.SSHCommand{
		Command: cmd,
		Jump:    strings.Join(jumpHosts, ","),
		Target:  targetAddr,
	})

	return commands
}

func generateSummary(hops []core.HopConfig, result *core.AnalysisResult) string {
	var parts []string

	successCount := 0
	for _, res := range result.Results {
		if len(res.IPs) > 0 {
			successCount++
		}
	}

	parts = append(parts, fmt.Sprintf("Analyzed %d hops, %d successful DNS resolutions",
		len(hops), successCount))

	if result.FirstResolved != nil {
		parts = append(parts, fmt.Sprintf("First resolution at: %s",
			result.FirstResolved.HopConfig.Host))
	} else {
		parts = append(parts, "No DNS resolution succeeded on any hop")
	}

	if len(result.SSHCommands) > 0 {
		parts = append(parts, fmt.Sprintf("Generated %d SSH command(s)",
			len(result.SSHCommands)))
	}

	return strings.Join(parts, "; ")
}
