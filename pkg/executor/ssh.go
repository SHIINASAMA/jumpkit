package executor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"jumpkit/pkg/core"
)

type Executor interface {
	Execute(target, command string) (string, error)
}

type LocalExecutor struct{}

func (e *LocalExecutor) Execute(_, command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "", fmt.Errorf("command failed: %s", errMsg)
	}

	return stdout.String(), nil
}

type SSHExecutor struct {
	SSHOptions []string
	AuthType   core.AuthType
	AuthToken  string
}

func (e *SSHExecutor) Execute(target, command string) (string, error) {
	sshArgs := buildSSHArgs(target, e.SSHOptions, e.AuthType, e.AuthToken, command)
	cmd := exec.Command("ssh", sshArgs...)

	if e.AuthType == core.AuthTypePassword && e.AuthToken != "" {
		env, cleanup, err := setupAskPass(e.AuthToken)
		if err != nil {
			return "", err
		}
		defer cleanup()
		cmd.Env = append(os.Environ(), env...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := stderr.String()
		if errMsg == "" {
			errMsg = err.Error()
		}
		return "", fmt.Errorf("ssh command failed: %s", errMsg)
	}

	return stdout.String(), nil
}

func buildSSHArgs(target string, options []string, authType core.AuthType, authToken, command string) []string {
	args := make([]string, 0)
	args = append(args, options...)

	if authType == core.AuthTypePrivateKey && authToken != "" {
		args = append(args, "-i", authToken)
	}

	if authType == "" || authToken == "" {
		args = append(args, "-o", "BatchMode=yes")
	}

	args = append(args, target)
	if command != "" {
		args = append(args, command)
	}

	return args
}

func setupAskPass(password string) ([]string, func(), error) {
	f, err := os.CreateTemp("", "jumpkit-askpass-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create askpass script: %w", err)
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
	f.Close()

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
