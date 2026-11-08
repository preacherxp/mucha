package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) *historyStore {
	t.Helper()
	return &historyStore{path: filepath.Join(t.TempDir(), "nested", "history.json")}
}

func call(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: bad JSON %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

func TestSealRecordsCiphertextOnly(t *testing.T) {
	_, cert := testCert(t)
	store := testStore(t)
	h := routes("tok", "http://x", store)
	body, _ := json.Marshal(map[string]any{"cert": cert, "source": "prod", "form": form{
		Name: "db", Namespace: "prod", Scope: scopeStrict, Type: "Opaque",
		Data: map[string]string{"password": b64("plaintext-marker")}, Sealed: map[string]string{"kept": "AAAA"}}})
	if code, out := call(t, h, "POST", "/api/seal", string(body)); code != 200 || out["historyError"] != nil {
		t.Fatal(code, out)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "plaintext-marker") || strings.Contains(string(data), b64("plaintext-marker")) {
		t.Fatalf("plaintext reached the history file:\n%s", data)
	}
	if info, _ := os.Stat(store.path); info.Mode().Perm() != 0o600 {
		t.Errorf("history file mode is %v", info.Mode().Perm())
	}
	got, err := store.read()
	if err != nil || len(got.Sealed) != 1 {
		t.Fatal(got, err)
	}
	r := got.Sealed[0]
	if r.Name != "db" || r.Source != "prod" || r.Fingerprint == "" || strings.Join(r.Keys, ",") != "kept,password" || !strings.Contains(r.YAML, "SealedSecret") {
		t.Errorf("bad record: %+v", r)
	}
	if code, _ := call(t, h, "DELETE", "/api/history/sealed/"+r.ID, ""); code != 200 {
		t.Fatal(code)
	}
	if got, _ := store.read(); len(got.Sealed) != 0 {
		t.Error("entry not deleted")
	}
}

func TestFailedSealIsNotRecorded(t *testing.T) {
	_, cert := testCert(t)
	store := testStore(t)
	body, _ := json.Marshal(map[string]any{"cert": cert, "form": form{Name: "BAD", Scope: scopeStrict}})
	if code, _ := call(t, routes("tok", "http://x", store), "POST", "/api/seal", string(body)); code != 400 {
		t.Fatal(code)
	}
	if got, _ := store.read(); len(got.Sealed) != 0 {
		t.Error("failed seal was recorded")
	}
}

func TestCertHistoryDedupesAndKeepsName(t *testing.T) {
	_, cert := testCert(t)
	_, info, _ := parseCert(cert)
	store := testStore(t)
	if s, err := store.addCert(cert, info, "prod"); s != "prod" || err != nil {
		t.Fatal(s, err)
	}
	if s, _ := store.addCert(cert, info, pastedSource); s != "prod" {
		t.Errorf("pasting a known certificate renamed it to %q", s)
	}
	if s, _ := store.addCert(cert, info, "prod-eu"); s != "prod-eu" {
		t.Errorf("a real name did not replace the old one: %q", s)
	}
	if got, _ := store.read(); len(got.Certs) != 1 || got.Certs[0].Source != "prod-eu" || got.Certs[0].PEM != cert {
		t.Errorf("%+v", got.Certs)
	}
	if err := store.deleteCert(info.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.read(); len(got.Certs) != 0 {
		t.Error("certificate not deleted")
	}
}

func TestHistoryKeepsNewestUpToLimit(t *testing.T) {
	store := testStore(t)
	for i := range maxSealedHistory + 3 {
		if err := store.addSealed(form{Name: fmt.Sprint("s", i)}, "", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := store.read()
	if len(got.Sealed) != maxSealedHistory || got.Sealed[0].Name != fmt.Sprint("s", maxSealedHistory+2) {
		t.Errorf("%d entries, newest %q", len(got.Sealed), got.Sealed[0].Name)
	}
}

func TestCorruptHistoryIsNotOverwritten(t *testing.T) {
	_, cert := testCert(t)
	store := testStore(t)
	os.MkdirAll(filepath.Dir(store.path), 0o700)
	os.WriteFile(store.path, []byte("{broken"), 0o600)
	h := routes("tok", "http://x", store)
	if code, _ := call(t, h, "GET", "/api/history", ""); code != 400 {
		t.Error("corrupt history was not reported:", code)
	}
	// Sealing still has to work, and must report the problem instead of replacing the file.
	body, _ := json.Marshal(map[string]any{"cert": cert, "form": form{Name: "db", Namespace: "n", Scope: scopeStrict, Type: "Opaque", Data: map[string]string{"k": b64("v")}}})
	code, out := call(t, h, "POST", "/api/seal", string(body))
	if code != 200 || out["yaml"] == "" || out["historyError"] == nil {
		t.Errorf("%d %v", code, out)
	}
	if data, _ := os.ReadFile(store.path); string(data) != "{broken" {
		t.Errorf("file was overwritten: %s", data)
	}
}
