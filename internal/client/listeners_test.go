package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"veil/internal/proto"
)

func TestLocalListeners(t *testing.T) {
	psk := bytes.Repeat([]byte{0x7}, proto.PSKSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan string, 4)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Config{
			Listen:     "127.0.0.1:0",
			HTTPListen: "127.0.0.1:0",
			DNSListen:  "127.0.0.1:0",
			ServerAddr: "127.0.0.1:9",
			PSK:        psk,
			OnListen: func(addr string) {
				events <- "socks " + addr
			},
			OnHTTPListen: func(addr string) {
				events <- "http " + addr
			},
			OnDNSListen: func(addr string) {
				events <- "dns " + addr
			},
		})
	}()

	got := map[string]string{}
	deadline := time.After(3 * time.Second)
	for len(got) < 3 {
		select {
		case ev := <-events:
			kind, addr, _ := splitEvent(ev)
			got[kind] = addr
		case <-deadline:
			t.Fatalf("события: %+v", got)
		}
	}
	if got["socks"] == "" || got["http"] == "" || got["dns"] == "" {
		t.Fatalf("адреса: %+v", got)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("не остановился")
	}
}

func TestHTTPOff(t *testing.T) {
	psk := bytes.Repeat([]byte{0x7}, proto.PSKSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan string, 4)
	go func() {
		_ = Run(ctx, Config{
			Listen:     "127.0.0.1:0",
			HTTPListen: "-",
			ServerAddr: "127.0.0.1:9",
			PSK:        psk,
			OnListen: func(addr string) {
				events <- "socks " + addr
			},
			OnHTTPListen: func(addr string) {
				events <- "http " + addr
			},
			OnDNSListen: func(string) {
				events <- "dns"
			},
		})
	}()
	deadline := time.After(3 * time.Second)
	var socks, http string
	n := 0
	for n < 2 {
		select {
		case ev := <-events:
			kind, addr, _ := splitEvent(ev)
			switch kind {
			case "socks":
				socks = addr
			case "http":
				http = addr
			case "dns":
				t.Fatal("DNS включился")
			}
			n++
		case <-deadline:
			t.Fatal("нет событий")
		}
	}
	select {
	case ev := <-events:
		t.Fatalf("лишнее событие %s", ev)
	default:
	}
	if socks == "" || http != "" {
		t.Fatalf("socks %q http %q", socks, http)
	}
	cancel()
}

func splitEvent(ev string) (string, string, bool) {
	for i := 0; i < len(ev); i++ {
		if ev[i] == ' ' {
			return ev[:i], ev[i+1:], true
		}
	}
	return ev, "", false
}
