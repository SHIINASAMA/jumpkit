package tui

import (
	"fmt"
	"strconv"
	"strings"

	"jumpkit/pkg/analyzer"
	"jumpkit/pkg/config"
	"jumpkit/pkg/core"
	"jumpkit/pkg/logger"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	styleRow    = lipgloss.NewStyle()
	styleCursor = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("4")).Background(lipgloss.Color("8"))
	styleEdit   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2")).Background(lipgloss.Color("0"))
	styleSelect = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")).Background(lipgloss.Color("0"))
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5")).MarginBottom(1)
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

type field int

const (
	fieldHost field = iota
	fieldPort
	fieldUser
	fieldAuthType
	fieldAuthToken
	fieldDNS
	fieldCount
)

var fieldNames = []string{"Host", "Port", "User", "AuthType", "AuthToken", "DNS"}

var selectOptions = map[field][]string{
	fieldAuthType: {string(core.AuthTypePrivateKey), string(core.AuthTypePassword)},
	fieldDNS:      {"n", "y"},
}

type mode int

const (
	modeNav      mode = iota
	modeEditText
	modeSelect
	modeRunning
	modeResult
	modeSavePrompt
)

type model struct {
	mode       mode
	hops       []core.HopConfig
	row        int
	col        int
	editBuf    string
	selIdx     int
	selOptions []string
	logs       []string
	statusMsg  string
	saveBuf    string
}

func InitialModel(loadPath string) model {
	m := model{mode: modeNav}
	if loadPath != "" {
		if hops, err := config.Load(loadPath); err == nil {
			m.hops = hops
			m.statusMsg = styleOK.Render(fmt.Sprintf("loaded %d hops from %s", len(hops), loadPath))
		} else {
			m.statusMsg = styleErr.Render(fmt.Sprintf("load failed: %v", err))
		}
	}
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case logMsg:
		m.logs = append(m.logs, msg.line)
		return m, waitForLog(msg.ch)
	case doneMsg:
		m.mode = modeResult
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := key.String()
	switch m.mode {
	case modeNav:
		return m.updateNav(k)
	case modeEditText:
		return m.updateEditText(k)
	case modeSelect:
		return m.updateSelect(k)
	case modeRunning:
		return m.updateRunning(k)
	case modeResult:
		if k == "esc" {
			m.mode = modeNav
		}
		return m, nil
	case modeSavePrompt:
		return m.updateSavePrompt(k)
	}
	return m, nil
}

func (m model) updateNav(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.row > 0 {
			m.row--
		}
	case "down", "j":
		if m.row < len(m.hops)-1 {
			m.row++
		}
	case "left", "h":
		if m.col > 0 {
			m.col--
		}
	case "right", "l":
		if m.col < int(fieldCount)-1 {
			m.col++
		}
	case "i", "enter":
		if len(m.hops) > 0 {
			return m.beginEdit()
		}
	case "a", "n":
		newHop := core.HopConfig{Port: 22}
		if len(m.hops) > 0 && m.row < len(m.hops)-1 {
			m.hops = append(m.hops[:m.row+1], append([]core.HopConfig{newHop}, m.hops[m.row+1:]...)...)
			m.row++
		} else {
			m.hops = append(m.hops, newHop)
			m.row = len(m.hops) - 1
		}
		m.col = 0
		return m.beginEdit()
	case "d", "backspace":
		if len(m.hops) > 0 {
			m.hops = append(m.hops[:m.row], m.hops[m.row+1:]...)
			if m.row >= len(m.hops) && m.row > 0 {
				m.row--
			}
		}
	case "r":
		if len(m.hops) >= 1 {
			m.mode = modeRunning
			m.logs = nil
			ch := make(chan string, 64)
			return m, tea.Batch(m.runAnalysis(ch), waitForLog(ch))
		}
	case "ctrl+s":
		m.mode = modeSavePrompt
		m.saveBuf = ""
		m.statusMsg = ""
		return m, nil
	case "ctrl+o":
		m.statusMsg = styleErr.Render("use: tui <path> to load")
		return m, nil
	}
	return m, nil
}

func (m model) beginEdit() (tea.Model, tea.Cmd) {
	f := field(m.col)
	if opts, ok := selectOptions[f]; ok {
		m.mode = modeSelect
		m.selOptions = opts
		m.editBuf = m.getCellValue(m.row, m.col)
		m.selIdx = 0
		for i, o := range opts {
			if o == m.editBuf {
				m.selIdx = i
				break
			}
		}
		return m, nil
	}
	m.mode = modeEditText
	m.editBuf = m.getCellValue(m.row, m.col)
	return m, nil
}

func (m model) updateEditText(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.mode = modeNav
		return m, nil
	case "enter":
		m.setCellValue(m.row, m.col, m.editBuf)
		m.mode = modeNav
		m.advanceCursor()
		return m, nil
	case "tab":
		m.setCellValue(m.row, m.col, m.editBuf)
		m.advanceCursor()
		return m.beginEdit()
	case "shift+tab":
		m.setCellValue(m.row, m.col, m.editBuf)
		m.retreatCursor()
		return m.beginEdit()
	case "backspace":
		if len(m.editBuf) > 0 {
			m.editBuf = m.editBuf[:len(m.editBuf)-1]
		}
		return m, nil
	default:
		if len(k) == 1 {
			m.editBuf += k
		}
	}
	return m, nil
}

func (m model) updateSelect(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.mode = modeNav
		return m, nil
	case "up", "k":
		if m.selIdx > 0 {
			m.selIdx--
		}
	case "down", "j":
		if m.selIdx < len(m.selOptions)-1 {
			m.selIdx++
		}
	case "enter":
		m.setCellValue(m.row, m.col, m.selOptions[m.selIdx])
		m.mode = modeNav
		m.advanceCursor()
		return m, nil
	case "tab":
		m.setCellValue(m.row, m.col, m.selOptions[m.selIdx])
		m.advanceCursor()
		return m.beginEdit()
	case "shift+tab":
		m.setCellValue(m.row, m.col, m.selOptions[m.selIdx])
		m.retreatCursor()
		return m.beginEdit()
	}
	return m, nil
}

func (m model) updateRunning(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "esc", "ctrl+c":
		m.mode = modeNav
		m.logs = nil
		return m, nil
	}
	return m, nil
}

func (m model) updateSavePrompt(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.mode = modeNav
		return m, nil
	case "enter":
		name := strings.TrimSpace(m.saveBuf)
		path, err := config.SavePath(name)
		if err != nil {
			m.statusMsg = styleErr.Render(err.Error())
			m.mode = modeNav
			return m, nil
		}
		if err := config.Save(path, m.hops); err != nil {
			m.statusMsg = styleErr.Render(err.Error())
		} else {
			m.statusMsg = styleOK.Render(fmt.Sprintf("saved %s", path))
		}
		m.mode = modeNav
		return m, nil
	case "backspace":
		if len(m.saveBuf) > 0 {
			m.saveBuf = m.saveBuf[:len(m.saveBuf)-1]
		}
		return m, nil
	default:
		if len(k) == 1 {
			m.saveBuf += k
		}
	}
	return m, nil
}

type logMsg struct {
	line string
	ch   chan string
}
type doneMsg struct{}

type channelWriter struct {
	ch  chan string
	buf []byte
}

func (w *channelWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if len(line) > 0 {
			w.ch <- line
		}
	}
	return len(p), nil
}

func (m model) runAnalysis(ch chan string) tea.Cmd {
	return func() tea.Msg {
		hops := make([]core.HopConfig, len(m.hops))
		copy(hops, m.hops)
		log := logger.New(logger.LevelInfo)
		log.SetOutput(&channelWriter{ch: ch})
		a := analyzer.New(log)
		a.Analyze(hops)
		close(ch)
		return doneMsg{}
	}
}

func waitForLog(ch chan string) tea.Cmd {
	return func() tea.Msg {
		line, ok := <-ch
		if !ok {
			return nil
		}
		return logMsg{line: line, ch: ch}
	}
}

func (m *model) advanceCursor() {
	if m.col < int(fieldCount)-1 {
		m.col++
	} else if m.row < len(m.hops)-1 {
		m.col = 0
		m.row++
	}
}

func (m *model) retreatCursor() {
	if m.col > 0 {
		m.col--
	} else if m.row > 0 {
		m.col = int(fieldCount) - 1
		m.row--
	}
}

func (m model) getCellValue(row, col int) string {
	if row >= len(m.hops) {
		return ""
	}
	hop := m.hops[row]
	switch field(col) {
	case fieldHost:
		return hop.Host
	case fieldPort:
		if hop.Port == 0 {
			return ""
		}
		return strconv.Itoa(hop.Port)
	case fieldUser:
		return hop.User
	case fieldAuthType:
		return string(hop.AuthType)
	case fieldAuthToken:
		return hop.AuthToken
	case fieldDNS:
		if hop.UseInternalDns {
			return "y"
		}
		return "n"
	}
	return ""
}

func (m *model) setCellValue(row, col int, val string) {
	if row >= len(m.hops) {
		return
	}
	hop := &m.hops[row]
	switch field(col) {
	case fieldHost:
		hop.Host = val
	case fieldPort:
		if val == "" {
			hop.Port = 0
		} else if p, err := strconv.Atoi(val); err == nil {
			hop.Port = p
		}
	case fieldUser:
		hop.User = val
	case fieldAuthType:
		hop.AuthType = core.AuthType(val)
	case fieldAuthToken:
		hop.AuthToken = val
	case fieldDNS:
		hop.UseInternalDns = val == "y"
	}
}

func (m model) View() string {
	switch m.mode {
	case modeRunning:
		return m.viewRunning()
	case modeResult:
		return m.viewResult()
	default:
		return m.viewTable()
	}
}

func (m model) viewTable() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("JumpKit - SSH Jump Chain Analyzer"))
	b.WriteString("\n")
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	for i := range m.hops {
		b.WriteString(m.renderRow(i))
		b.WriteString("\n")
	}

	if len(m.hops) == 0 {
		b.WriteString(styleDim.Render("  (no hops - press 'a' to add)"))
		b.WriteString("\n")
	}

	if m.statusMsg != "" {
		b.WriteString("\n  " + m.statusMsg)
	}

	b.WriteString("\n")
	b.WriteString(m.renderStatus())

	if m.mode == modeSavePrompt {
		b.WriteString(m.renderSavePrompt())
	}

	if m.mode == modeSelect {
		b.WriteString(m.renderSelectPopup())
	}

	return b.String()
}

func (m model) viewRunning() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("JumpKit - Analyzing..."))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 70))
	b.WriteString("\n")
	for _, line := range m.logs {
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.logs) == 0 {
		b.WriteString(styleDim.Render("  starting analysis..."))
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("-", 70))
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  esc: cancel"))
	return b.String()
}

func (m model) viewResult() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("JumpKit - Result"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 70))
	b.WriteString("\n")
	for _, line := range m.logs {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("-", 70))
	b.WriteString("\n\n")
	b.WriteString(styleDim.Render("  esc: back"))
	return b.String()
}

func (m model) renderSavePrompt() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(styleDim.Render("  Save config (name or /absolute/path):"))
	b.WriteString("\n")
	b.WriteString(styleEdit.Render(fmt.Sprintf("  > %s_", m.saveBuf)))
	b.WriteString("\n\n")
	b.WriteString(styleDim.Render("  enter: save | esc: cancel"))
	return b.String()
}

var colWidths = []int{20, 7, 10, 12, 20, 5}

func (m model) renderHeader() string {
	var parts []string
	for i, name := range fieldNames {
		s := fmt.Sprintf("%-*s", colWidths[i], name)
		parts = append(parts, styleHeader.Render(s))
	}
	return "  " + strings.Join(parts, "")
}

func (m model) renderRow(idx int) string {
	hop := m.hops[idx]
	rawValues := []string{
		hop.Host,
		portStr(hop.Port),
		hop.User,
		string(hop.AuthType),
		hop.AuthToken,
		boolStr(hop.UseInternalDns),
	}

	var parts []string
	for i, val := range rawValues {
		pad := colWidths[i]
		display := val

		if field(i) == fieldAuthToken && len(val) > 0 {
			isEditing := m.mode == modeEditText && idx == m.row && i == m.col
			if !isEditing {
				display = maskStr(val)
			}
		}

		cell := fmt.Sprintf("%-*s", pad, truncate(display, pad))

		if idx == m.row {
			if i == m.col {
				switch m.mode {
				case modeEditText:
					cursor := m.editBuf
					if field(i) == fieldAuthToken {
						cursor = maskStr(cursor)
					}
					cell = fmt.Sprintf("%-*s", pad, truncate(cursor+"_", pad))
					parts = append(parts, styleEdit.Render(cell))
					continue
				case modeSelect:
					cell = fmt.Sprintf("%-*s", pad, truncate(display+"▼", pad))
					parts = append(parts, styleSelect.Render(cell))
					continue
				}
				parts = append(parts, styleCursor.Render(cell))
			} else {
				parts = append(parts, styleCursor.Render(cell))
			}
		} else {
			parts = append(parts, styleRow.Render(cell))
		}
	}

	cursor := "  "
	if idx == m.row {
		cursor = styleCursor.Render("→ ")
	}
	return cursor + strings.Join(parts, "")
}

func (m model) renderSelectPopup() string {
	xOffset := 2
	for i := 0; i < m.col; i++ {
		xOffset += colWidths[i]
	}

	var lines []string
	lines = append(lines, "")
	prefix := strings.Repeat(" ", xOffset)
	for i, opt := range m.selOptions {
		marker := " "
		if i == m.selIdx {
			marker = ">"
		}
		lines = append(lines, prefix+styleSelect.Render(fmt.Sprintf(" %s %s", marker, opt)))
	}
	lines = append(lines, prefix+styleDim.Render("up/down:select enter:ok esc:cancel"))
	return strings.Join(lines, "\n")
}

func (m model) renderStatus() string {
	var keys []string
	switch m.mode {
	case modeNav:
		keys = []string{
			"↑↓←→:move", "i/enter:edit", "a:add", "d:del",
			"r:run", "ctrl+s:save", "ctrl+o:load", "q:quit",
		}
	case modeEditText:
		keys = []string{"enter:ok", "tab:next", "esc:cancel"}
	case modeSelect:
		keys = []string{"↑↓:select", "enter:ok", "esc:cancel"}
	case modeSavePrompt:
		keys = []string{"enter:save", "esc:cancel"}
	case modeResult:
		keys = []string{"any key:back"}
	}
	return styleDim.Render("  " + strings.Join(keys, " | "))
}

func portStr(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}

func boolStr(b bool) string {
	if b {
		return "y"
	}
	return "n"
}

func maskStr(s string) string {
	if len(s) == 0 {
		return ""
	}
	n := len(s)
	if n > 16 {
		n = 16
	}
	return strings.Repeat("*", n)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
