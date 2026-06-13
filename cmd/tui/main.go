// Package main JumpKit TUI 入口程序。
//
// 用法：
//   go run ./cmd/tui                  # 空白启动
//   go run ./cmd/tui path/to/config.json  # 加载配置启动
package main

import (
	"fmt"
	"os"

	"jumpkit/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	var loadPath string
	if len(os.Args) > 1 {
		loadPath = os.Args[1]
	}

	p := tea.NewProgram(tui.InitialModel(loadPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
