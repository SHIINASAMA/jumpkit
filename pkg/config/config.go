package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"jumpkit/pkg/core"
)

func SavePath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("name required")
	}

	if strings.HasPrefix(name, "/") {
		return name + ".json", nil
	}

	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.HasPrefix(name, "..") {
		return "", fmt.Errorf("invalid config name: %q", name)
	}

	return name + ".json", nil
}

func Save(path string, hops []core.HopConfig) error {
	cfg := struct {
		Hops []core.HopConfig `json:"hops"`
	}{Hops: hops}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func Load(path string) ([]core.HopConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg struct {
		Hops []core.HopConfig `json:"hops"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg.Hops, nil
}
