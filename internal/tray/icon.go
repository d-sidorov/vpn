package tray

import (
	_ "embed"
	"encoding/binary"
	"errors"
)

//go:embed icon.ico
var iconICO []byte

func iconImage(ico []byte) ([]byte, error) {
	if len(ico) < 22 || binary.LittleEndian.Uint16(ico[0:2]) != 0 || binary.LittleEndian.Uint16(ico[2:4]) != 1 {
		return nil, errors.New("битая иконка")
	}
	if binary.LittleEndian.Uint16(ico[4:6]) < 1 {
		return nil, errors.New("битая иконка")
	}
	size := int(binary.LittleEndian.Uint32(ico[14:18]))
	off := int(binary.LittleEndian.Uint32(ico[18:22]))
	if size <= 0 || off < 0 || off+size > len(ico) {
		return nil, errors.New("битая иконка")
	}
	return ico[off : off+size], nil
}
