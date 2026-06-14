package executor

import (
	"fmt"

	"jumpkit/pkg/core"
)

// BuildPasswordMap 从 hops 中提取所有密码认证的主机，构建 "user@host" → password 映射。
func BuildPasswordMap(hops []core.HopConfig) map[string]string {
	m := make(map[string]string)
	for _, h := range hops {
		if h.AuthType == core.AuthTypePassword && h.AuthToken != "" {
			m[fmt.Sprintf("%s@%s", h.User, h.Host)] = h.AuthToken
		}
	}
	return m
}
