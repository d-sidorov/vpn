package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"testing"

	"veil/internal/profile"
	"veil/internal/proto"
)

func flagPSK(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, proto.PSKSize))
}

func connectFlags(t *testing.T, args []string) (*flag.FlagSet, *string, *string, *string, *string, *string, *string, *bool) {
	t.Helper()
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	server := fs.String("server", "", "")
	sni := fs.String("sni", "", "")
	listen := fs.String("listen", "127.0.0.1:1080", "")
	httpListen := fs.String("http", "127.0.0.1:8080", "")
	dnsListen := fs.String("dns", "", "")
	psk := fs.String("psk", "", "")
	insecure := fs.Bool("insecure", false, "")
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs, server, sni, listen, httpListen, dnsListen, psk, insecure
}

func TestMergeExplicitFlags(t *testing.T) {
	fileKey := bytes.Repeat([]byte{0x11}, proto.PSKSize)
	fs, server, sni, listen, httpListen, dnsListen, psk, insecure := connectFlags(t, []string{
		"-server", "override:443",
		"-sni", "",
		"-insecure=false",
	})
	cfg, err := mergeConnect(fs, profile.Settings{
		Server:     "file.example:443",
		SNI:        "file.example",
		Listen:     "10.0.0.8:1080",
		HTTPListen: "10.0.0.8:8080",
		DNSListen:  "10.0.0.8:5353",
		PSK:        fileKey,
		Insecure:   true,
	}, true, *server, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != "override:443" {
		t.Fatalf("server: %s", cfg.ServerAddr)
	}
	if cfg.SNI != "" {
		t.Fatalf("пустой -sni не перекрыл файл: %q", cfg.SNI)
	}
	if cfg.Listen != "10.0.0.8:1080" {
		t.Fatalf("listen по умолчанию перекрыл файл: %s", cfg.Listen)
	}
	if cfg.HTTPListen != "10.0.0.8:8080" || cfg.DNSListen != "10.0.0.8:5353" {
		t.Fatalf("локальные адреса по умолчанию перекрыли файл: %+v", cfg)
	}
	if !bytes.Equal(cfg.PSK, fileKey) {
		t.Fatal("psk файла затёрт без -psk")
	}
	if cfg.Insecure {
		t.Fatal("-insecure=false не перекрыл файл")
	}
}

func TestMergeNoSource(t *testing.T) {
	fs, server, sni, listen, httpListen, dnsListen, psk, insecure := connectFlags(t, []string{
		"-server", "h:443",
		"-psk", flagPSK(0x22),
	})
	cfg, err := mergeConnect(fs, profile.Settings{Listen: "10.9.9.9:1", Insecure: true}, false, *server, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != "h:443" || cfg.Listen != "127.0.0.1:1080" || cfg.HTTPListen != "127.0.0.1:8080" || cfg.DNSListen != "" || cfg.Insecure || cfg.SNI != "" {
		t.Fatalf("без источника: %+v", cfg)
	}
	if !bytes.Equal(cfg.PSK, bytes.Repeat([]byte{0x22}, proto.PSKSize)) {
		t.Fatal("psk флага")
	}

	fs, server, sni, listen, httpListen, dnsListen, psk, insecure = connectFlags(t, nil)
	if _, err := mergeConnect(fs, profile.Settings{}, false, *server, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure); err == nil {
		t.Fatal("пустой ключ принят")
	}
}

func TestMergeLocalListeners(t *testing.T) {
	fileKey := bytes.Repeat([]byte{0x11}, proto.PSKSize)
	base := profile.Settings{
		Server:     "file.example:443",
		Listen:     "10.0.0.8:1080",
		HTTPListen: "10.0.0.8:8080",
		DNSListen:  "10.0.0.8:5353",
		PSK:        fileKey,
	}
	fs, server, sni, listen, httpListen, dnsListen, psk, insecure := connectFlags(t, []string{
		"-http", "-",
		"-dns", "127.0.0.1:5353",
	})
	cfg, err := mergeConnect(fs, base, true, *server, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPListen != "-" || cfg.DNSListen != "127.0.0.1:5353" {
		t.Fatalf("явные флаги: %+v", cfg)
	}
	if cfg.Listen != "10.0.0.8:1080" || cfg.ServerAddr != "file.example:443" {
		t.Fatalf("файл затёрт: %+v", cfg)
	}

	fs, server, sni, listen, httpListen, dnsListen, psk, insecure = connectFlags(t, nil)
	cfg, err = mergeConnect(fs, profile.Settings{
		Server: "file.example:443",
		PSK:    fileKey,
	}, true, *server, *sni, *listen, *httpListen, *dnsListen, *psk, *insecure)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPListen != "127.0.0.1:8080" || cfg.DNSListen != "" || cfg.Listen != "127.0.0.1:1080" {
		t.Fatalf("пустой файл: %+v", cfg)
	}
}
