package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

func main() {
	noOpen := flag.Bool("no-open", false, "do not open a browser")
	addr := flag.String("addr", "127.0.0.1:0", "listen address (keep it on loopback)")
	historyPath := flag.String("history", defaultHistoryPath(), "history file for sealed output and certificates")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := serve(ctx, *addr, *noOpen, &historyStore{path: *historyPath}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, addr string, noOpen bool, store *historyStore) error {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	token := hex.EncodeToString(b)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	origin := "http://" + ln.Addr().String()
	url := origin + "/#token=" + token
	fmt.Println(url)
	if !noOpen {
		_ = openBrowser(url)
	}
	server := &http.Server{Handler: routes(token, origin, store), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	if err := server.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func routes(token, origin string, store *historyStore) http.Handler {
	static, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	api := func(pattern string, h func(*http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && o != origin {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			v, err := h(r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				v = map[string]string{"error": err.Error()}
			}
			_ = json.NewEncoder(w).Encode(v)
		})
	}

	api("GET /api/contexts", func(r *http.Request) (any, error) {
		out, err := run(r.Context(), "kubectl", "config", "get-contexts", "-o", "name")
		if err != nil {
			return nil, err
		}
		current, _ := run(r.Context(), "kubectl", "config", "current-context")
		return map[string]any{"contexts": strings.Fields(out), "current": strings.TrimSpace(current)}, nil
	})

	api("GET /api/namespaces", func(r *http.Request) (any, error) {
		args := []string{"get", "namespaces", "-o", "name", "--request-timeout=8s"}
		if c := r.URL.Query().Get("context"); c != "" {
			args = append(args, "--context="+c)
		}
		out, err := run(r.Context(), "kubectl", args...)
		if err != nil {
			return nil, err
		}
		names := strings.Fields(strings.ReplaceAll(out, "namespace/", ""))
		return map[string]any{"namespaces": names}, nil
	})

	api("POST /api/cert", func(r *http.Request) (any, error) {
		var req struct{ PEM, Context, ControllerNamespace, ControllerName, Source string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		if req.PEM == "" {
			if !dnsLabel.MatchString(req.ControllerNamespace) || !dnsLabel.MatchString(req.ControllerName) {
				return nil, errors.New("controller namespace and name must be valid Kubernetes names")
			}
			args := []string{"--fetch-cert", "--controller-namespace=" + req.ControllerNamespace, "--controller-name=" + req.ControllerName}
			if req.Context != "" {
				args = append(args, "--context="+req.Context)
			}
			out, err := run(r.Context(), "kubeseal", args...)
			if err != nil {
				return nil, err
			}
			req.PEM = out
		}
		_, info, err := parseCert(req.PEM)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"pem": req.PEM, "info": info}
		source, err := store.addCert(req.PEM, info, req.Source)
		out["source"] = source
		if err != nil { // the certificate is still usable, so report this instead of failing
			out["historyError"] = "Could not save to history: " + err.Error()
		}
		return out, nil
	})

	api("POST /api/import", func(r *http.Request) (any, error) {
		var req struct{ Text string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		f, kind, err := importDoc(req.Text)
		if err != nil {
			return nil, err
		}
		masked, err := maskedOriginal(req.Text, kind)
		return map[string]any{"form": f, "kind": kind, "masked": masked}, err
	})

	api("POST /api/seal", func(r *http.Request) (any, error) {
		var req struct {
			Cert, Source string
			Form         form
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		out, err := seal(req.Cert, req.Form)
		if err != nil {
			return nil, err
		}
		resp := map[string]string{"yaml": string(out)}
		_, info, _ := parseCert(req.Cert) // seal already validated it
		if err := store.addSealed(req.Form, req.Source, info.Fingerprint, out); err != nil {
			resp["historyError"] = "Could not save to history: " + err.Error()
		}
		return resp, nil
	})

	api("GET /api/history", func(*http.Request) (any, error) {
		h, err := store.read()
		return map[string]any{"sealed": h.Sealed, "certs": h.Certs, "path": store.path}, err
	})

	api("DELETE /api/history/sealed/{id}", func(r *http.Request) (any, error) {
		return map[string]bool{"ok": true}, store.deleteSealed(r.PathValue("id"))
	})

	api("DELETE /api/history/certs/{fingerprint}", func(r *http.Request) (any, error) {
		return map[string]bool{"ok": true}, store.deleteCert(r.PathValue("fingerprint"))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s: %s", name, msg)
	}
	return string(out), nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	}
	return nil
}
