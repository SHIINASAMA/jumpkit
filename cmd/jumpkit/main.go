package main

import (
	"fmt"
	"os"

	"github.com/alexflint/go-arg"
	"golang.org/x/term"

	"jumpkit/pkg/analyzer"
	"jumpkit/pkg/config"
	"jumpkit/pkg/core"
	"jumpkit/pkg/executor"
	"jumpkit/pkg/logger"
	"jumpkit/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

type args struct {
	Config   string `arg:"-c,--config" help:"Run CLI mode from config file"`
	Connect  bool   `arg:"-x,--connect" help:"Connect interactively to the target after analysis"`
	Tunnel   int    `arg:"-p,--tunnel" help:"Open local port forwarding tunnel (specify local port)"`
	LoadPath string `arg:"positional" help:"Config file to load in TUI (optional)"`
}

func main() {
	var a args
	a.Tunnel = -1
	arg.MustParse(&a)

	if a.Config != "" {
		if a.Tunnel == -1 {
			a.Tunnel = 0
		}
		runCLI(a)
		return
	}

	runTUI(a.LoadPath)
}

func runCLI(a args) {
	hops, err := config.Load(a.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	for i := range hops {
		if hops[i].AuthType != "" && hops[i].AuthToken == "" {
			fmt.Fprintf(os.Stderr, "Enter %s for %s: ", hops[i].AuthType, hops[i].Host)
			token, err := readPassword()
			fmt.Fprintln(os.Stderr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read password: %v\n", err)
				os.Exit(1)
			}
			hops[i].AuthToken = token
		}
	}

	var action core.SSHAction
	tunnelPort := a.Tunnel
	if a.Tunnel > 0 {
		action = core.ActionTunnel
	} else if a.Connect {
		action = core.ActionConnect
	}

	opts := analyzer.AnalysisOptions{
		Action:     action,
		TunnelPort: tunnelPort,
	}

	log := logger.New(logger.LevelDebug)
	ana := analyzer.New(log)
	result := ana.Analyze(hops, opts)

	if action == core.ActionConnect || action == core.ActionTunnel {
		if len(result.SSHCommands) == 0 {
			fmt.Fprintf(os.Stderr, "No SSH command generated\n")
			os.Exit(1)
		}
		cmd := result.SSHCommands[0]
		exec := executorFromResult(result)
		if err := exec.Connect(cmd.Command); err != nil {
			fmt.Fprintf(os.Stderr, "connect: %v\n", err)
			os.Exit(1)
		}
	}
}

func executorFromResult(result *core.AnalysisResult) *executor.SSHExecutor {
	e := &executor.SSHExecutor{Timeout: 0}
	if len(result.Hops) > 0 {
		hop := result.Hops[len(result.Hops)-1]
		e.AuthType = hop.AuthType
		e.AuthToken = hop.AuthToken
	}
	return e
}

func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	token, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func runTUI(loadPath string) {
	p := tea.NewProgram(tui.InitialModel(loadPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
