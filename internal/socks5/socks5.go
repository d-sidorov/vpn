package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// ErrHandled значит, что отрицательный ответ клиенту уже записан.
var ErrHandled = errors.New("socks: ответ отправлен")

func ReadRequest(conn net.Conn) (string, uint16, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != 5 || hdr[1] == 0 {
		return "", 0, errors.New("socks: не SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
	}
	for _, m := range methods {
		if m == 0 {
			if _, err := conn.Write([]byte{5, 0}); err != nil {
				return "", 0, err
			}
			return readCommand(conn)
		}
	}
	_, _ = conn.Write([]byte{5, 0xff})
	return "", 0, ErrHandled
}

func Reply(conn net.Conn, ok bool) error {
	rep := byte(1)
	if ok {
		rep = 0
	}
	_, err := conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func readCommand(conn net.Conn) (string, uint16, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != 5 {
		return "", 0, errors.New("socks: плохой запрос")
	}
	if hdr[1] != 1 {
		_ = Reply(conn, false)
		return "", 0, ErrHandled
	}
	host, port, err := readAddr(conn, hdr[3])
	if err != nil {
		_ = Reply(conn, false)
		return "", 0, ErrHandled
	}
	return host, port, nil
}

func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	switch atyp {
	case 1:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:]), nil
	case 4:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:]), nil
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}
		if n[0] == 0 {
			return "", 0, errors.New("socks: пустое имя")
		}
		b := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host := string(b[:n[0]])
		port := binary.BigEndian.Uint16(b[n[0]:])
		return host, port, nil
	default:
		return "", 0, errors.New("socks: тип адреса")
	}
}
