package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	maxSealedHistory = 100
	maxCertHistory   = 50
	pastedSource     = "pasted certificate"
)

// sealedRecord holds only ciphertext and names. Plaintext never reaches this file.
type sealedRecord struct {
	ID          string    `json:"id"`
	At          time.Time `json:"at"`
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	Scope       string    `json:"scope"`
	Keys        []string  `json:"keys"`
	Source      string    `json:"source"`
	Fingerprint string    `json:"fingerprint"`
	YAML        string    `json:"yaml"`
}

type certRecord struct {
	certInfo
	PEM        string    `json:"pem"`
	Source     string    `json:"source"`
	LastLoaded time.Time `json:"lastLoaded"`
}

type history struct {
	Sealed []sealedRecord `json:"sealed"`
	Certs  []certRecord   `json:"certs"`
}

type historyStore struct {
	path string
	mu   sync.Mutex
}

func defaultHistoryPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "mucha", "history.json")
}

func (s *historyStore) read() (history, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *historyStore) load() (history, error) {
	h := history{Sealed: []sealedRecord{}, Certs: []certRecord{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return h, fmt.Errorf("history file %s is unreadable, so it was left untouched: %w", s.path, err)
	}
	return h, nil
}

// update reads from disk every time, so two running copies do not undo each other's entries.
// shortcut: no file lock, two writes at the same instant can still lose one entry; add one if that ever matters.
func (s *historyStore) update(change func(*history)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.load()
	if err != nil {
		return err // never overwrite a file we could not parse
	}
	change(&h)
	data, err := json.MarshalIndent(h, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "history-*.json") // CreateTemp makes it 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (s *historyStore) addSealed(f form, source, fingerprint string, yaml []byte) error {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	keys := slices.Sorted(maps.Keys(f.Data))
	keys = append(keys, slices.Sorted(maps.Keys(f.Sealed))...)
	slices.Sort(keys)
	rec := sealedRecord{ID: hex.EncodeToString(id), At: time.Now(), Name: f.Name, Namespace: f.Namespace, Scope: f.Scope,
		Keys: slices.Compact(keys), Source: source, Fingerprint: fingerprint, YAML: string(yaml)}
	return s.update(func(h *history) {
		h.Sealed = slices.Insert(h.Sealed, 0, rec)
		h.Sealed = h.Sealed[:min(len(h.Sealed), maxSealedHistory)]
	})
}

// addCert returns the name to show for the certificate: pasting a known one keeps the name it already has.
func (s *historyStore) addCert(pem string, info certInfo, source string) (string, error) {
	if source == "" {
		source = pastedSource
	}
	err := s.update(func(h *history) {
		for _, c := range h.Certs {
			if c.Fingerprint == info.Fingerprint && source == pastedSource {
				source = c.Source
			}
		}
		h.Certs = slices.DeleteFunc(h.Certs, func(c certRecord) bool { return c.Fingerprint == info.Fingerprint })
		h.Certs = slices.Insert(h.Certs, 0, certRecord{certInfo: info, PEM: pem, Source: source, LastLoaded: time.Now()})
		h.Certs = h.Certs[:min(len(h.Certs), maxCertHistory)]
	})
	return source, err
}

func (s *historyStore) deleteSealed(id string) error {
	return s.update(func(h *history) {
		h.Sealed = slices.DeleteFunc(h.Sealed, func(r sealedRecord) bool { return r.ID == id })
	})
}

func (s *historyStore) deleteCert(fingerprint string) error {
	return s.update(func(h *history) {
		h.Certs = slices.DeleteFunc(h.Certs, func(c certRecord) bool { return c.Fingerprint == fingerprint })
	})
}
