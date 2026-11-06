//go:build !windows

package tray

import "errors"

// Icon на системах без трея не создаётся.
type Icon struct{}

func Supported() bool { return false }

func Open(string, func()) (*Icon, error) {
	return nil, errors.New("трей поддерживается только в Windows")
}

func (i *Icon) Close() {}
