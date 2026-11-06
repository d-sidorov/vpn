package server

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"veil/internal/proto"
)

func newServer(cfg Config) (*Server, error) {
	s := &Server{allowLoopback: cfg.AllowLoopback}
	if len(cfg.PSK) > 0 {
		if len(cfg.PSK) != proto.PSKSize {
			return nil, errors.New("psk должен быть 32 байта")
		}
		s.static = [][]byte{append([]byte(nil), cfg.PSK...)}
	}
	if cfg.KeysFile != "" {
		keys, err := LoadKeys(cfg.KeysFile)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(cfg.KeysFile)
		if err != nil {
			return nil, err
		}
		s.filePath = cfg.KeysFile
		s.fileKeys = keys
		s.fileMtime = fi.ModTime()
	}
	if len(s.static)+len(s.fileKeys) == 0 {
		return nil, errors.New("нужен хотя бы один ключ")
	}
	s.page = newPage(s.firstLocked())
	return s, nil
}

func (s *Server) snapshot() (keys [][]byte, page []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked()
	keys = make([][]byte, 0, len(s.static)+len(s.fileKeys))
	keys = append(keys, s.static...)
	keys = append(keys, s.fileKeys...)
	return keys, s.page
}

func (s *Server) reloadLocked() {
	if s.filePath == "" {
		return
	}
	fi, err := os.Stat(s.filePath)
	if err != nil {
		s.noteReadErr(err)
		return
	}
	if !s.fileMtime.IsZero() && fi.ModTime().Equal(s.fileMtime) {
		return
	}
	keys, err := LoadKeys(s.filePath)
	if err != nil {
		s.noteReadErr(err)
		return
	}
	s.fileKeys = keys
	s.fileMtime = fi.ModTime()
	s.readErrLogged = false
	if first := s.firstLocked(); first != nil {
		s.page = newPage(first)
	}
}

// Ошибка чтения не должна обнулять ключи: иначе сбой диска закроет всех клиентов.
func (s *Server) noteReadErr(err error) {
	if s.readErrLogged {
		return
	}
	s.readErrLogged = true
	log.Printf("ключи: %v", err)
}

func (s *Server) firstLocked() []byte {
	if len(s.static) > 0 {
		return s.static[0]
	}
	if len(s.fileKeys) > 0 {
		return s.fileKeys[0]
	}
	return nil
}

func LoadKeys(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKeys(data)
}

func parseKeys(data []byte) ([][]byte, error) {
	var keys [][]byte
	for i, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trim == "" || strings.Contains(trim, "#") {
			continue
		}
		key, err := proto.ParsePSK(trim)
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", i+1, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func RemoveKey(path string, key []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	found := false
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		raw := strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(raw)
		if trim != "" && !strings.Contains(trim, "#") {
			parsed, err := proto.ParsePSK(trim)
			if err == nil && bytes.Equal(parsed, key) {
				found = true
				continue
			}
		}
		kept = append(kept, raw)
	}
	if !found {
		return errors.New("ключа нет в файле")
	}
	body := strings.Join(kept, "\n")
	if strings.HasSuffix(string(data), "\n") && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return writeFile(path, []byte(body))
}

func writeFile(path string, data []byte) error {
	perm := os.FileMode(0600)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".keys-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(path)
		if err2 := os.Rename(tmp, path); err2 != nil {
			os.Remove(tmp)
			return err2
		}
	}
	return nil
}
