package server

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAndRevokeKeys(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	enc := func(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
	dir := t.TempDir()
	path := filepath.Join(dir, "keys")
	text := "# люди\n\n" + enc(first) + "\nзаметка # не ключ\n" + enc(second) + "\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !bytes.Equal(keys[0], first) || !bytes.Equal(keys[1], second) {
		t.Fatalf("ключи: %d", len(keys))
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("не-ключ\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(bad); err == nil {
		t.Fatal("битая строка принята")
	}

	missing := bytes.Repeat([]byte{0x33}, 32)
	if err := RemoveKey(path, missing); err == nil || strings.Contains(err.Error(), enc(missing)) {
		t.Fatalf("чужой ключ: %v", err)
	}
	same, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(same) != text {
		t.Fatalf("файл изменён: %q", same)
	}

	if err := RemoveKey(path, second); err != nil {
		t.Fatal(err)
	}
	left, err := LoadKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || !bytes.Equal(left[0], first) {
		t.Fatal("после отзыва остался не тот ключ")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# люди") || strings.Contains(string(body), enc(second)) {
		t.Fatalf("файл после отзыва: %q", body)
	}
}

func TestPageUsesFirstKey(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	path := filepath.Join(t.TempDir(), "keys")
	line := base64.StdEncoding.EncodeToString(second) + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(Config{PSK: first, KeysFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.page, newPage(first)) || bytes.Equal(newPage(first), newPage(second)) {
		t.Fatal("страница считается не от первого ключа")
	}
}

func TestReloadKeepsKeysOnReadError(t *testing.T) {
	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	path := filepath.Join(t.TempDir(), "keys")
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(2 * time.Second)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
	}
	write(base64.StdEncoding.EncodeToString(second) + "\n")
	s, err := newServer(Config{PSK: first, KeysFile: path})
	if err != nil {
		t.Fatal(err)
	}
	write("мусор\n")
	keys, _ := s.snapshot()
	if len(keys) != 2 || !bytes.Equal(keys[1], second) {
		t.Fatal("ошибка чтения обнулила ключи")
	}
	keys, _ = s.snapshot()
	if len(keys) != 2 {
		t.Fatal("повторный снимок потерял ключи")
	}

	write(base64.StdEncoding.EncodeToString(first) + "\n")
	keys, _ = s.snapshot()
	if len(keys) != 2 || !bytes.Equal(keys[0], first) || !bytes.Equal(keys[1], first) {
		t.Fatalf("после правки файла ключей %d", len(keys))
	}
}
