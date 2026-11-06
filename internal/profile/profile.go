package profile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"veil/internal/proto"
)

// Settings — параметры клиента из JSON-файла или ссылки veil://.
type Settings struct {
	Server     string
	SNI        string
	Listen     string
	HTTPListen string
	DNSListen  string
	PSK        []byte
	Insecure   bool
}

type document struct {
	Server     string `json:"server"`
	PSK        string `json:"psk"`
	SNI        string `json:"sni,omitempty"`
	Listen     string `json:"listen,omitempty"`
	HTTPListen string `json:"httpListen,omitempty"`
	DNSListen  string `json:"dns,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

func Load(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, fmt.Errorf("не удалось прочитать файл: %w", err)
	}
	return decode(data, false)
}

// ParseURL читает veil:// и raw base64url того же JSON, что и файл.
// listen, httpListen и dns отбрасываются: это адреса на машине клиента.
func ParseURL(raw string) (Settings, error) {
	raw = strings.TrimSpace(raw)
	const scheme = "veil://"
	if !strings.HasPrefix(raw, scheme) {
		return Settings{}, errors.New("ссылка должна начинаться с veil://")
	}
	payload := raw[len(scheme):]
	if payload == "" {
		return Settings{}, errors.New("не удалось разобрать ссылку")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Settings{}, errors.New("не удалось разобрать ссылку")
	}
	return decode(data, true)
}

// FormatURL собирает ссылку без listen, httpListen и dns.
func FormatURL(server, sni, psk string, insecure bool) (string, error) {
	server = strings.TrimSpace(server)
	sni = strings.TrimSpace(sni)
	psk = strings.TrimSpace(psk)
	if server == "" {
		return "", errors.New("не задан адрес сервера")
	}
	if _, err := proto.ParsePSK(psk); err != nil {
		return "", err
	}
	body, err := json.Marshal(document{
		Server:   server,
		PSK:      psk,
		SNI:      sni,
		Insecure: insecure,
	})
	if err != nil {
		return "", err
	}
	return "veil://" + base64.RawURLEncoding.EncodeToString(body), nil
}

func decode(data []byte, dropListen bool) (Settings, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Settings{}, errors.New("не удалось прочитать параметры")
	}
	doc.Server = strings.TrimSpace(doc.Server)
	doc.SNI = strings.TrimSpace(doc.SNI)
	doc.Listen = strings.TrimSpace(doc.Listen)
	doc.HTTPListen = strings.TrimSpace(doc.HTTPListen)
	doc.DNSListen = strings.TrimSpace(doc.DNSListen)
	if doc.Server == "" {
		return Settings{}, errors.New("не задан адрес сервера")
	}
	key, err := proto.ParsePSK(doc.PSK)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{
		Server:   doc.Server,
		SNI:      doc.SNI,
		PSK:      key,
		Insecure: doc.Insecure,
	}
	if !dropListen {
		out.Listen = doc.Listen
		out.HTTPListen = doc.HTTPListen
		out.DNSListen = doc.DNSListen
	}
	return out, nil
}
