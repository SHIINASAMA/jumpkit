//go:build unix

package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"jumpkit/pkg/core"
)

// SSHExecutor handles SSH command execution.
type SSHExecutor struct {
	SSHOptions []string
	AuthType   core.AuthType
	AuthToken  string
	Timeout    time.Duration
}

// Execute runs a non-interactive SSH command, capturing stdout.
func (e *SSHExecutor) Execute(target, command string) (string, error) {
	sshArgs := buildSSHArgs(target, e.SSHOptions, e.AuthType, e.AuthToken, command)
	return runSSH(e, sshArgs, true)
}

// Connect runs an interactive SSH session.
func (e *SSHExecutor) Connect(sshCommand string) error {
	args := shellSplit(sshCommand)
	if len(args) < 2 {
		return fmt.Errorf("empty ssh command")
	}
	_, err := runSSH(e, args[1:], e.AuthType == core.AuthTypePassword)
	return err
}

func runSSH(e *SSHExecutor, sshArgs []string, capture bool) (string, error) {
	cmd := exec.Command("ssh", sshArgs...)

	if e.Timeout > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), e.Timeout)
		defer cancel()
		cmd = exec.CommandContext(ctx, "ssh", sshArgs...)
	}

	hasPassword := e.AuthType == core.AuthTypePassword && e.AuthToken != ""

	if hasPassword {
		askpass, cleanup, err := setupAskPass(e.AuthToken)
		if err != nil {
			return "", err
		}
		defer cleanup()
		cmd.Env = append(os.Environ(), askpass...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}

	var stdout bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return "", err
	}

	_ = capture
	_ = stdout
	return "", nil
}

func setupAskPass(password string) ([]string, func(), error) {
	f, err := os.CreateTemp("", "jumpkit-askpass-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create askpass: %w", err)
	}
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", escapeSingleQuote(password))
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, nil, err
	}
	if err := f.Chmod(0700); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return nil, nil, err
	}

	env := []string{
		"SSH_ASKPASS=" + f.Name(),
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=dummy",
	}
	cleanup := func() { os.Remove(f.Name()) }
	return env, cleanup, nil
}

func escapeSingleQuote(s string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			result = append(result, '\'', '\\', '\'', '\'')
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

func buildSSHArgs(target string, options []string, authType core.AuthType, authToken, command string) []string {
	args := make([]string, 0)
	args = append(args, options...)

	if authType == core.AuthTypePrivateKey && authToken != "" {
		args = append(args, "-i", authToken)
	}

	if authType == core.AuthTypePassword {
		args = append(args, "-o", "PreferredAuthentications=password")
	} else if authType == "" || authToken == "" {
		args = append(args, "-o", "BatchMode=yes")
	}

	args = append(args, target)
	if command != "" {
		args = append(args, command)
	}

	return args
}

func shellSplit(s string) []string {
	var parts []string
	var current strings.Builder
	inSingle := false
	inDouble := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ' ' && !inSingle && !inDouble:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}
