//go:build !windows

package main

func launchWithoutArgs() (bool, error) {
	return false, nil
}
