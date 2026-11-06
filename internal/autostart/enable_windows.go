//go:build windows

package autostart

import (
	"errors"
	"os"

	"golang.org/x/sys/windows/registry"
)

func Enable(configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	line, err := CommandLine(exe, configPath)
	if err != nil {
		return err
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runName, line)
}

func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	err = k.DeleteValue(runName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}
