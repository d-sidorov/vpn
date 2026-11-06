package autostart

import (
	"errors"
	"path/filepath"
	"strings"
)

const (
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	runName = "Veil"
)

// CommandLine собирает значение автозапуска: абсолютный путь exe и connect -config.
// PSK, -psk и -url в строку не входят.
func CommandLine(exe, configPath string) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return "", errors.New("нужен -config: ключ не должен попасть в реестр")
	}
	absExe, err := filepath.Abs(exe)
	if err != nil {
		return "", err
	}
	absCfg, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	return quoteArg(absExe) + " connect -config " + quoteArg(absCfg), nil
}

func quoteArg(s string) string {
	if s == "" || strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
