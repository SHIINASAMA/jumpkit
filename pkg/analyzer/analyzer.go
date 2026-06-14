package analyzer

import (
	"fmt"
	"strings"
	"time"

	"jumpkit/pkg/core"
	"jumpkit/pkg/executor"
	"jumpkit/pkg/logger"
	"jumpkit/pkg/resolver"
)

const defaultSSHTimeout = 15 * time.Second

type AnalysisOptions struct {
	Action     core.SSHAction
	TunnelPort int
}

type Analyzer struct {
	log *logger.Logger
}

func New(log *logger.Logger) *Analyzer {
	return &Analyzer{
		log: log,
	}
}

func (a *Analyzer) Analyze(hops []core.HopConfig, opts AnalysisOptions) *core.AnalysisResult {
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
		opts = append(opts, identityArgs(hops[:i+1])...)
		opts = append(opts, "-o", "StrictHostKeyChecking=no", "-o", "ForwardAgent=yes")
		exec := &executor.SSHExecutor{
			SSHOptions: opts,
			AuthType:   hop.AuthType,
			AuthToken:  hop.AuthToken,
			Timeout:    defaultSSHTimeout,
		}

		hopResult := core.HopResult{HopConfig: hop}

		doDNS := !resolved && !hop.UseInternalDns

		if doDNS {
			cmd := resolver.FormatDNSCommand(dnsCmd, targetDomain)
			hopResult.Command = cmd
			out, err := exec.Execute(sshTarget, cmd)
			hopResult.Output = out
			hopResult.Err = err

			if err != nil {
				a.log.Step(i+1, len(hops), "%s ✗", hop.Host)
				a.log.Info("%s", err)
			} else {
				a.log.Step(i+1, len(hops), "%s ✓", hop.Host)
				ips := resolver.ParseDNSOutput(out, cmd)
				hopResult.IPs = ips
				if len(ips) > 0 {
					a.log.Info("dns %s → %s", targetDomain, strings.Join(ips, ", "))
					if result.FirstResolved == nil {
						first := hopResult
						result.FirstResolved = &first
						result.TargetIP = hopResult.IPs[0]
						resolved = true
					}
				}
			}
		} else {
			out, err := exec.Execute(sshTarget, "echo ok")
			hopResult.Output = out
			hopResult.Err = err
			hopResult.Command = "echo ok"
			if err != nil {
				a.log.Step(i+1, len(hops), "%s ✗", hop.Host)
				a.log.Info("%s", err)
			} else {
				a.log.Step(i+1, len(hops), "%s ✓", hop.Host)
			}
		}

		result.Results = append(result.Results, hopResult)
		jumpChain = append(jumpChain, chainEntry)
	}

	result.SSHCommands = generateSSHCommands(hops, result, opts)
	result.Summary = generateSummary(hops, result)

	for _, cmd := range result.SSHCommands {
		a.log.Info("%s", cmd)
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

func identityArgs(hops []core.HopConfig) []string {
	var args []string
	for _, hop := range hops {
		if hop.AuthType == core.AuthTypePrivateKey && hop.AuthToken != "" {
			args = append(args, "-i", hop.AuthToken)
		}
	}
	if len(args) > 0 {
		args = append(args, "-o", "IdentitiesOnly=yes")
	}
	return args
}

func generateSSHCommands(hops []core.HopConfig, result *core.AnalysisResult, opts AnalysisOptions) []core.SSHCommand {
	if len(hops) < 2 {
		return nil
	}

	targetHop := hops[len(hops)-1]

	var jumpHosts []string
	for i := 0; i < len(hops)-1; i++ {
		jumpHosts = append(jumpHosts, formatSSHTarget(hops[i], true))
	}

	targetAddr := targetHop.Host
	if result.TargetIP != "" {
		targetAddr = result.TargetIP
	}

	var args []string
	var execArgs []string

	execArgs = append(execArgs, identityArgs(hops)...)
	execArgs = append(execArgs, "-o", "StrictHostKeyChecking=no", "-o", "ForwardAgent=yes")

	if targetHop.AuthType == core.AuthTypePassword {
		execArgs = append(execArgs, "-o", "PreferredAuthentications=password")
	}

	if len(jumpHosts) > 0 {
		args = append(args, "-J", strings.Join(jumpHosts, ","))
	}
	port := targetHop.Port
	if port == 0 {
		port = 22
	}

	switch opts.Action {
	case core.ActionTunnel:
		localPort := opts.TunnelPort
		if localPort == 0 {
			localPort = port
		}
		args = append(args, "-D", fmt.Sprintf("%d", localPort))
		if port != 0 && port != 22 {
			args = append(args, "-p", fmt.Sprintf("%d", port))
		}
		if targetHop.User != "" {
			args = append(args, fmt.Sprintf("%s@%s", targetHop.User, targetAddr))
		} else {
			args = append(args, targetAddr)
		}
	default:
		if targetHop.AuthType != core.AuthTypePassword {
			execArgs = append(execArgs, "-t")
		}
		if port != 0 && port != 22 {
			args = append(args, "-p", fmt.Sprintf("%d", port))
		}
		if targetHop.User != "" {
			args = append(args, fmt.Sprintf("%s@%s", targetHop.User, targetAddr))
		} else {
			args = append(args, targetAddr)
		}
	}

	displayCmd := fmt.Sprintf("ssh %s", strings.Join(args, " "))
	allArgs := append(execArgs, args...)
	fullCmd := fmt.Sprintf("ssh %s", strings.Join(allArgs, " "))
	return []core.SSHCommand{{
		Command:    fullCmd,
		Display:    displayCmd,
		Action:     opts.Action,
		TunnelPort: opts.TunnelPort,
	}}
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
