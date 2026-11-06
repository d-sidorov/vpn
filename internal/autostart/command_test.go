package autostart

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandLine(t *testing.T) {
	exe := filepath.Join("Program Files", "veil.exe")
	cfg := filepath.Join("my dir", "client.json")
	line, err := CommandLine(exe, cfg)
	if err != nil {
		t.Fatal(err)
	}
	absExe, err := filepath.Abs(exe)
	if err != nil {
		t.Fatal(err)
	}
	absCfg, err := filepath.Abs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := quoteArg(absExe) + " connect -config " + quoteArg(absCfg)
	if line != want {
		t.Fatalf("строка %q, хотели %q", line, want)
	}
	if !strings.Contains(line, " connect -config ") {
		t.Fatal(line)
	}
	lower := strings.ToLower(line)
	if strings.Contains(lower, "psk") || strings.Contains(line, "-url") || strings.Contains(line, "veil://") {
		t.Fatalf("в командную строку попал секрет: %s", line)
	}
	if !strings.HasPrefix(line, `"`) || !strings.Contains(line, `" connect -config "`) {
		t.Fatalf("пути с пробелом не закавычены: %s", line)
	}
	if runName != "Veil" || !strings.Contains(runKey, `CurrentVersion\Run`) {
		t.Fatalf("ключ реестра %s %s", runKey, runName)
	}
	if _, err := CommandLine(exe, "  "); err == nil {
		t.Fatal("пустой -config принят")
	}
}

func TestCommandLinePlainPath(t *testing.T) {
	line, err := CommandLine("veil.exe", "client.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, `"`) {
		t.Fatalf("кавычки без пробела: %s", line)
	}
}
