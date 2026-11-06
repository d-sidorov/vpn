//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole        = kernel32.NewProc("FreeConsole")
)

// ownConsole отличает двойной щелчок от запуска в уже открытой консоли.
// У нового окна в списке только сам процесс. В PowerShell рядом есть оболочка.
func ownConsole() bool {
	var ids [2]uint32
	n, _, _ := procConsoleProcessList.Call(uintptr(unsafe.Pointer(&ids[0])), uintptr(len(ids)))
	return n == 1
}

func launchWithoutArgs() (bool, error) {
	if !ownConsole() {
		return false, nil
	}
	_, _, _ = procFreeConsole.Call()
	path, ok := configBesideExe()
	if !ok {
		tell("Рядом с программой нет файла client.json.\nПоложите его в ту же папку и запустите снова.")
		return true, errors.New("рядом нет client.json")
	}
	err := connect([]string{"-config", path})
	if err != nil {
		tell(err.Error())
	}
	return true, err
}

func configBesideExe() (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	path := filepath.Join(filepath.Dir(exe), "client.json")
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return "", false
	}
	return path, true
}

func tell(text string) {
	caption, err := windows.UTF16PtrFromString("Veil")
	if err != nil {
		return
	}
	body, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	const mbOK = 0x00000000
	const mbIcon = 0x00000040
	const mbForeground = 0x00010000
	_, _ = windows.MessageBox(0, body, caption, mbOK|mbIcon|mbForeground)
}
