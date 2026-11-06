package profile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPSKString() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
}

func TestFileToLink(t *testing.T) {
	psk := testPSKString()
	body := `{
		"server": "vpn.example:443",
		"psk": "` + psk + `",
		"sni": "vpn.example",
		"listen": "10.1.2.3:9050",
		"httpListen": "10.1.2.3:8080",
		"dns": "10.1.2.3:5353",
		"insecure": true,
		"note": "ignored"
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if fromFile.Server != "vpn.example:443" || fromFile.SNI != "vpn.example" || !fromFile.Insecure {
		t.Fatalf("файл: %+v", fromFile)
	}
	if !bytes.Equal(fromFile.PSK, bytes.Repeat([]byte{0x11}, 32)) {
		t.Fatal("psk из файла разошёлся")
	}
	if fromFile.Listen != "10.1.2.3:9050" {
		t.Fatalf("listen файла: %q", fromFile.Listen)
	}
	if fromFile.HTTPListen != "10.1.2.3:8080" || fromFile.DNSListen != "10.1.2.3:5353" {
		t.Fatalf("локальные адреса файла: %+v", fromFile)
	}

	link, err := FormatURL(fromFile.Server, fromFile.SNI, psk, fromFile.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "veil://"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("listen")) || bytes.Contains(raw, []byte(`"dns"`)) {
		t.Fatalf("ссылка содержит локальный адрес: %s", raw)
	}
	fromLink, err := ParseURL(link)
	if err != nil {
		t.Fatal(err)
	}
	if fromLink.Server != fromFile.Server || fromLink.SNI != fromFile.SNI || fromLink.Insecure != fromFile.Insecure {
		t.Fatalf("ссылка: %+v", fromLink)
	}
	if !bytes.Equal(fromLink.PSK, fromFile.PSK) {
		t.Fatal("psk ссылки разошёлся")
	}
	if fromLink.Listen != "" || fromLink.HTTPListen != "" || fromLink.DNSListen != "" {
		t.Fatalf("локальный адрес из ссылки: %+v", fromLink)
	}

	withListen, err := json.Marshal(map[string]any{
		"server":     "vpn.example:443",
		"psk":        psk,
		"sni":        "vpn.example",
		"listen":     "10.9.9.9:1",
		"httpListen": "10.9.9.9:8080",
		"dns":        "10.9.9.9:5353",
		"insecure":   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseURL("veil://" + base64.RawURLEncoding.EncodeToString(withListen))
	if err != nil {
		t.Fatal(err)
	}
	if got.Listen != "" || got.HTTPListen != "" || got.DNSListen != "" || got.Server != "vpn.example:443" || !got.Insecure {
		t.Fatalf("локальный адрес из чужой ссылки применился: %+v", got)
	}
	if !bytes.Equal(got.PSK, fromFile.PSK) {
		t.Fatal("psk чужой ссылки разошёлся")
	}
}

func TestReject(t *testing.T) {
	psk := testPSKString()
	shortLink, err := json.Marshal(map[string]string{"server": "h:443", "psk": "aa"})
	if err != nil {
		t.Fatal(err)
	}
	emptyServer, err := json.Marshal(map[string]string{"server": "  ", "psk": psk})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := FormatURL("h:443", "name", psk, false)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		url  string
		file string
	}{
		{name: "битая ссылка", url: "veil://!!!!"},
		{name: "пустая ссылка", url: "veil://"},
		{name: "чужая схема", url: "https://example/" + strings.TrimPrefix(valid, "veil://")},
		{name: "схема без слэшей", url: "veil:" + strings.TrimPrefix(valid, "veil://")},
		{name: "короткий psk в ссылке", url: "veil://" + base64.RawURLEncoding.EncodeToString(shortLink)},
		{name: "пустой server в ссылке", url: "veil://" + base64.RawURLEncoding.EncodeToString(emptyServer)},
		{name: "короткий psk в файле", file: `{"server":"h:443","psk":"aa"}`},
		{name: "пустой server в файле", file: `{"server":"","psk":"` + psk + `"}`},
		{name: "битый json", file: `{`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.url != "" {
				if _, err := ParseURL(tc.url); err == nil {
					t.Fatal("ссылка принята")
				}
			}
			if tc.file != "" {
				dir := t.TempDir()
				path := filepath.Join(dir, "bad.json")
				if err := os.WriteFile(path, []byte(tc.file), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := Load(path); err == nil {
					t.Fatal("файл принят")
				}
			}
		})
	}

	if _, err := FormatURL("", "name", psk, false); err == nil {
		t.Fatal("пустой server в ссылке принят")
	}
	if _, err := FormatURL("h:443", "", "aa", true); err == nil {
		t.Fatal("короткий psk в ссылке принят")
	}
}
