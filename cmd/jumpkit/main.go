package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"jumpkit/pkg/analyzer"
	"jumpkit/pkg/config"
	"jumpkit/pkg/logger"
	"jumpkit/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	cliConfig := flag.String("c", "", "Run CLI from config file")
	flag.Parse()

	if *cliConfig != "" {
		runCLI(*cliConfig)
		return
	}

	var loadPath string
	if args := flag.Args(); len(args) > 0 {
		loadPath = args[0]
	}
	runTUI(loadPath)
}

func runCLI(path string) {
	hops, err := config.Load(path)
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

	log := logger.New(logger.LevelDebug)
	a := analyzer.New(log)
	a.Analyze(hops)
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
