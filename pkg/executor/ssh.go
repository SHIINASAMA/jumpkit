package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"jumpkit/pkg/core"
)

type SSHExecutor struct {
	SSHOptions []string
	AuthType   core.AuthType
	AuthToken  string
	Timeout    time.Duration
}

func (e *SSHExecutor) Execute(target, command string) (string, error) {
	sshArgs := buildSSHArgs(target, e.SSHOptions, e.AuthType, e.AuthToken, command)

	ctx := context.Background()
	if e.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)

	if e.AuthType == core.AuthTypePassword && e.AuthToken != "" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdin = strings.NewReader(e.AuthToken + "\n")
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
