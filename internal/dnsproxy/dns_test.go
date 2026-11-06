package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("локальный резолвер")
		},
	}
	os.Exit(m.Run())
}

func TestForwardsToCloudflareTCP(t *testing.T) {
	query := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	type hit struct {
		host string
		port uint16
		wire []byte
	}
	hits := make(chan hit, 1)
	pc := listenUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Serve(ctx, pc, func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(b, hdr[:]); err != nil {
					hits <- hit{host: host, port: port}
					return
				}
				n := int(binary.BigEndian.Uint16(hdr[:]))
				body := make([]byte, n)
				if _, err := io.ReadFull(b, body); err != nil {
					hits <- hit{host: host, port: port, wire: append(hdr[:], body...)}
					return
				}
				wire := append(hdr[:], body...)
				hits <- hit{host: host, port: port, wire: append([]byte(nil), wire...)}
				resp := make([]byte, 2+len(body))
				binary.BigEndian.PutUint16(resp[:2], uint16(len(body)))
				copy(resp[2:], body)
				_, _ = b.Write(resp)
			}()
			return a, nil
		})
	}()

	client := listenUDP(t)
	if _, err := client.WriteTo(query, pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(buf[:n], query) {
		t.Fatalf("ответ: %x", buf[:n])
	}
	select {
	case h := <-hits:
		if h.host != "1.1.1.1" || h.port != 53 {
			t.Fatalf("dial: %s:%d", h.host, h.port)
		}
		if len(h.wire) < 2 || binary.BigEndian.Uint16(h.wire[:2]) != uint16(len(query)) || !bytesEqual(h.wire[2:], query) {
			t.Fatalf("tcp: %x", h.wire)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial не вызван")
	}
}

func TestDialErrorSERVFAIL(t *testing.T) {
	query := []byte{0x11, 0x22, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pc := listenUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = Serve(ctx, pc, func(context.Context, string, uint16) (net.Conn, error) {
			return nil, errors.New("туннель")
		})
	}()
	client := listenUDP(t)
	if _, err := client.WriteTo(query, pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _, err := client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 || buf[0] != 0x11 || buf[1] != 0x22 || buf[3]&0x0f != 2 {
		t.Fatalf("servfail: %x", buf[:n])
	}
}

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
