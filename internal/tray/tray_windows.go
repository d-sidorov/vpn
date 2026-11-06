//go:build windows

package tray

import (
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmNull         = 0x0000
	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmContextMenu  = 0x007B
	wmLButtonUp    = 0x0202
	wmRButtonUp    = 0x0205
	wmUser         = 0x0400
	wmTray         = wmUser + 1
	mfString       = 0x0000
	mfGrayed       = 0x0001
	mfDisabled     = 0x0002
	mfSeparator    = 0x0800
	tpmReturnCmd   = 0x0100
	tpmNonotify    = 0x0080
	tpmRightButton = 0x0002
	nimAdd         = 0x00000000
	nimDelete      = 0x00000002
	nifMessage     = 0x00000001
	nifIcon        = 0x00000002
	nifTip         = 0x00000004
	idExit         = 2
)

// Окно Win32 живёт на создавшем его потоке, поэтому цикл сообщений закреплён.
type Icon struct {
	hwnd   uintptr
	hicon  uintptr
	onExit func()
	done   chan struct{}

	mu      sync.Mutex
	status  string
	pumping bool
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW         = user32.NewProc("RegisterClassExW")
	pCreateWindowExW          = user32.NewProc("CreateWindowExW")
	pDefWindowProcW           = user32.NewProc("DefWindowProcW")
	pGetMessageW              = user32.NewProc("GetMessageW")
	pTranslateMessage         = user32.NewProc("TranslateMessage")
	pDispatchMessageW         = user32.NewProc("DispatchMessageW")
	pPostMessageW             = user32.NewProc("PostMessageW")
	pPostQuitMessage          = user32.NewProc("PostQuitMessage")
	pDestroyWindow            = user32.NewProc("DestroyWindow")
	pCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	pDestroyMenu              = user32.NewProc("DestroyMenu")
	pAppendMenuW              = user32.NewProc("AppendMenuW")
	pTrackPopupMenu           = user32.NewProc("TrackPopupMenu")
	pSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	pGetCursorPos             = user32.NewProc("GetCursorPos")
	pCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	pDestroyIcon              = user32.NewProc("DestroyIcon")
	pGetModuleHandleW         = kernel32.NewProc("GetModuleHandleW")
	pShellNotifyIconW         = shell32.NewProc("Shell_NotifyIconW")

	className  = windows.StringToUTF16("VeilTray")
	wndProcPtr = windows.NewCallback(wndProc)

	trayMu      sync.Mutex
	trayCurrent *Icon
)

type wndClass struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type notifyIconData struct {
	cbSize           uint32
	hwnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         [16]byte
	hBalloonIcon     uintptr
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	x       int32
	y       int32
}

type point struct {
	x int32
	y int32
}

func Supported() bool { return true }

func Open(status string, onExit func()) (*Icon, error) {
	ic := &Icon{
		onExit: onExit,
		done:   make(chan struct{}),
		status: status,
	}
	ready := make(chan error, 1)
	go ic.loop(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return ic, nil
}

func (ic *Icon) Close() {
	if ic == nil || ic.hwnd == 0 {
		return
	}
	pPostMessageW.Call(ic.hwnd, wmClose, 0, 0)
	<-ic.done
}

func (ic *Icon) loop(ready chan<- error) {
	runtime.LockOSThread()
	defer close(ic.done)
	if err := ic.start(); err != nil {
		ready <- err
		return
	}
	ready <- nil
	ic.mu.Lock()
	ic.pumping = true
	ic.mu.Unlock()
	ic.pump()
}

func (ic *Icon) start() error {
	hinst, _, _ := pGetModuleHandleW.Call(0)
	if hinst == 0 {
		return errors.New("не удалось создать значок в трее")
	}
	cls := wndClass{
		cbSize:        uint32(unsafe.Sizeof(wndClass{})),
		lpfnWndProc:   wndProcPtr,
		hInstance:     hinst,
		lpszClassName: &className[0],
	}
	atom, _, callErr := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&cls)))
	if atom == 0 && !errors.Is(callErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
		return errors.New("не удалось создать значок в трее")
	}

	trayMu.Lock()
	trayCurrent = ic
	trayMu.Unlock()

	hwnd, _, _ := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(&className[0])),
		uintptr(unsafe.Pointer(&className[0])),
		0,
		0, 0, 0, 0,
		0, 0,
		hinst,
		0,
	)
	if hwnd == 0 {
		ic.clearCurrent()
		return errors.New("не удалось создать значок в трее")
	}
	ic.hwnd = hwnd

	hicon, err := loadIcon()
	if err != nil {
		pDestroyWindow.Call(hwnd)
		ic.hwnd = 0
		ic.clearCurrent()
		return err
	}
	ic.hicon = hicon
	if err := ic.addIcon(); err != nil {
		pDestroyIcon.Call(hicon)
		ic.hicon = 0
		pDestroyWindow.Call(hwnd)
		ic.hwnd = 0
		ic.clearCurrent()
		return err
	}
	return nil
}

func (ic *Icon) clearCurrent() {
	trayMu.Lock()
	if trayCurrent == ic {
		trayCurrent = nil
	}
	trayMu.Unlock()
}

func (ic *Icon) pump() {
	defer ic.clearCurrent()
	for {
		var m winMsg
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func (ic *Icon) addIcon() error {
	nid := ic.notify(true)
	r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if r == 0 {
		return errors.New("не удалось создать значок в трее")
	}
	return nil
}

func (ic *Icon) removeIcon() {
	if ic.hwnd == 0 {
		return
	}
	nid := ic.notify(false)
	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	if ic.hicon != 0 {
		pDestroyIcon.Call(ic.hicon)
		ic.hicon = 0
	}
}

func (ic *Icon) notify(full bool) notifyIconData {
	nid := notifyIconData{
		cbSize: uint32(unsafe.Sizeof(notifyIconData{})),
		hwnd:   ic.hwnd,
		uID:    1,
	}
	if !full {
		return nid
	}
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTray
	nid.hIcon = ic.hicon
	ic.mu.Lock()
	status := ic.status
	ic.mu.Unlock()
	putUTF16(nid.szTip[:], status)
	return nid
}

func (ic *Icon) showMenu() {
	ic.mu.Lock()
	status := ic.status
	ic.mu.Unlock()
	if status == "" {
		status = "Veil"
	}
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer pDestroyMenu.Call(menu)
	appendText(menu, mfString|mfGrayed|mfDisabled, 1, status)
	pAppendMenuW.Call(menu, mfSeparator, 0, 0)
	appendText(menu, mfString, idExit, "Выход")

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(ic.hwnd)
	cmd, _, _ := pTrackPopupMenu.Call(
		menu,
		tpmReturnCmd|tpmNonotify|tpmRightButton,
		uintptr(uint32(pt.x)),
		uintptr(uint32(pt.y)),
		0,
		ic.hwnd,
		0,
	)
	pPostMessageW.Call(ic.hwnd, wmNull, 0, 0)
	if cmd == idExit && ic.onExit != nil {
		go ic.onExit()
	}
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	trayMu.Lock()
	ic := trayCurrent
	trayMu.Unlock()
	if ic != nil && hwnd == ic.hwnd && ic.handle(msg, lparam) {
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

func (ic *Icon) handle(msg, lparam uintptr) bool {
	switch msg {
	case wmTray:
		switch lparam {
		case wmRButtonUp, wmLButtonUp, wmContextMenu:
			ic.showMenu()
		}
		return true
	case wmClose:
		ic.removeIcon()
		pDestroyWindow.Call(ic.hwnd)
		return true
	case wmDestroy:
		// DestroyWindow до цикла сообщений не должен ставить WM_QUIT: поток ещё переиспользуют.
		ic.mu.Lock()
		pumping := ic.pumping
		ic.mu.Unlock()
		if pumping {
			pPostQuitMessage.Call(0)
		}
		return true
	default:
		return false
	}
}

func loadIcon() (uintptr, error) {
	img, err := iconImage(iconICO)
	if err != nil {
		return 0, err
	}
	h, _, _ := pCreateIconFromResourceEx.Call(
		uintptr(unsafe.Pointer(&img[0])),
		uintptr(len(img)),
		1,
		0x00030000,
		16,
		16,
		0,
	)
	runtime.KeepAlive(img)
	if h == 0 {
		return 0, errors.New("не удалось создать значок в трее")
	}
	return h, nil
}

func appendText(menu, flags, id uintptr, text string) {
	u := mustUTF16(text)
	pAppendMenuW.Call(menu, flags, id, uintptr(unsafe.Pointer(&u[0])))
	runtime.KeepAlive(u)
}

func mustUTF16(s string) []uint16 {
	u, err := windows.UTF16FromString(s)
	if err != nil || len(u) == 0 {
		return []uint16{0}
	}
	return u
}

func putUTF16(dst []uint16, s string) {
	for i := range dst {
		dst[i] = 0
	}
	runes := []rune(s)
	if len(runes) > len(dst)-1 {
		runes = runes[:len(dst)-1]
	}
	u, err := windows.UTF16FromString(string(runes))
	if err != nil {
		return
	}
	copy(dst, u)
}
