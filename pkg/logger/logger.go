package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	mu     sync.Mutex
	level  Level
	output io.Writer
}

func New(level Level) *Logger {
	return &Logger{
		level:  level,
		output: os.Stderr,
	}
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, "DBG", format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, "INF", format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, "WRN", format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, "ERR", format, args...)
}

func (l *Logger) log(level Level, tag, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level {
		return
	}
	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "[%s] %s %s\n", ts, tag, msg)
}

func (l *Logger) Print(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(l.output, msg)
}

func (l *Logger) Step(step int, total int, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "  [%d/%d] %s\n", step, total, msg)
}

func (l *Logger) Section(title string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.output, "\n━━━ %s ━━━\n", title)
}
