package executor

import (
	"time"

	"jumpkit/pkg/core"
)

type SSHExecutor struct {
	SSHOptions []string
	AuthType   core.AuthType
	AuthToken  string
	Timeout    time.Duration
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
