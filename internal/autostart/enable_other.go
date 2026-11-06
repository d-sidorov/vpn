//go:build !windows

package autostart

import "errors"

func Enable(string) error {
	return errors.New("автозапуск поддерживается только в Windows")
}

func Disable() error {
	return errors.New("автозапуск поддерживается только в Windows")
}
