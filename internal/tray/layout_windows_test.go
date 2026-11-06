//go:build windows

package tray

import (
	"testing"
	"unsafe"
)

func TestWin32Layout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("раскладка проверена для 64-bit")
	}
	if unsafe.Sizeof(notifyIconData{}) != 976 {
		t.Fatalf("NOTIFYICONDATA %d", unsafe.Sizeof(notifyIconData{}))
	}
	if unsafe.Sizeof(wndClass{}) != 80 {
		t.Fatalf("WNDCLASSEX %d", unsafe.Sizeof(wndClass{}))
	}
	if unsafe.Sizeof(winMsg{}) != 48 {
		t.Fatalf("MSG %d", unsafe.Sizeof(winMsg{}))
	}
}

func TestLoadIcon(t *testing.T) {
	h, err := loadIcon()
	if err != nil {
		t.Fatal(err)
	}
	if h == 0 {
		t.Fatal("пустой HICON")
	}
	pDestroyIcon.Call(h)
}
