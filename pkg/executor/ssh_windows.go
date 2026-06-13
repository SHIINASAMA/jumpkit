//go:build windows

package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"jumpkit/pkg/core"
)

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
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
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
