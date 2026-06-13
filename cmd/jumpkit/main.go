package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

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
	old, err := makeRaw(fd)
	if err != nil {
		return "", err
	}
	defer restore(fd, old)

	var buf [4]byte
	var result []byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if err != nil {
			return "", err
		}
		for i := 0; i < n; i++ {
			if buf[i] == '\n' || buf[i] == '\r' {
				return string(result), nil
			}
			result = append(result, buf[i])
		}
	}
}

func makeRaw(fd int) (*syscall.Termios, error) {
	var old syscall.Termios
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGETA, uintptr(noescape(unsafe.Pointer(&old))), 0, 0, 0); err != 0 {
		return nil, fmt.Errorf("tcgetattr: %w", err)
	}
	raw := old
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON
	if _, _, err := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSETA, uintptr(noescape(unsafe.Pointer(&raw))), 0, 0, 0); err != 0 {
		return nil, fmt.Errorf("tcsetattr: %w", err)
	}
	return &old, nil
}

func restore(fd int, old *syscall.Termios) {
	syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCSETA, uintptr(noescape(unsafe.Pointer(old))), 0, 0, 0)
}

func noescape(p unsafe.Pointer) unsafe.Pointer {
	return p
}

func runTUI(loadPath string) {
	p := tea.NewProgram(tui.InitialModel(loadPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
