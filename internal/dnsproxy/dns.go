package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const (
	upstreamHost = "1.1.1.1"
	upstreamPort = 53
	queryTimeout = 10 * time.Second
)

// Dial открывает TCP. Для DNS это всегда 1.1.1.1:53 внутри туннеля.
type DialFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Serve читает DNS по UDP и пересылает каждый запрос как есть в TCP-туннель.
// Свой резолвер не вызывается: нет ответа от туннеля — SERVFAIL или тишина.
func Serve(ctx context.Context, pc net.PacketConn, dial DialFunc) error {
	if dial == nil {
		return errors.New("не задан набор соединений")
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		q := make([]byte, n)
		copy(q, buf[:n])
		go handleQuery(ctx, pc, from, q, dial)
	}
}

func handleQuery(ctx context.Context, pc net.PacketConn, from net.Addr, query []byte, dial DialFunc) {
	if len(query) == 0 || len(query) > 65535 {
		return
	}
	qctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	conn, err := dial(qctx, upstreamHost, upstreamPort)
	if err != nil {
		writeSERVFAIL(pc, from, query)
		return
	}
	defer conn.Close()
	// DNS over TCP: 2 байта длины и сообщение. Локальный резолвер не вызывается.
	if err := writeTCP(conn, query); err != nil {
		writeSERVFAIL(pc, from, query)
		return
	}
	msg, err := readTCP(conn)
	if err != nil {
		writeSERVFAIL(pc, from, query)
		return
	}
	_, _ = pc.WriteTo(msg, from)
}

func writeTCP(w io.Writer, msg []byte) error {
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := writeAll(w, buf)
	return err
}

func readTCP(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("пустой ответ DNS")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func writeSERVFAIL(pc net.PacketConn, to net.Addr, query []byte) {
	if len(query) < 12 {
		return
	}
	msg := make([]byte, 12)
	msg[0], msg[1] = query[0], query[1]
	msg[2] = 0x81
	msg[3] = 0x82
	_, _ = pc.WriteTo(msg, to)
}
