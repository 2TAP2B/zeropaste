// zeropaste — zero-knowledge paste sharing in a single binary.
// Server stores only ciphertext; the AES-256-GCM key lives in the URL fragment.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const maxData = 64 << 10 // ciphertext cap; text/passwords/snippets only

// file-phase caps: env-tunable byte counts (raw integers, e.g. 2147483648).
var (
	maxBlobBytes  int64 = 2 << 30 // 2 GiB per share (whole-file in-memory encryption bound)
	chunkBytes    int64 = 8 << 20 // 8 MiB per chunk PUT / range GET
	burnWindowSec int64 = 30      // bundle burn: grace window after meta read (protocol needs it to finish downloading)
)

//go:embed web/index.html
var indexHTML []byte

//go:embed web/assets
var assetFS embed.FS

// parseTTL accepts free-form burn times: "10m", "10 min", "6h", "1d", "30 days".
// Ceiling: 30 days — this is a scratch box, not an archive.
func parseTTL(s string) (time.Duration, bool) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if s == "" {
		return 0, false
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i == len(s) {
		return 0, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil || n <= 0 {
		return 0, false
	}
	switch s[i:] {
	case "m", "min", "mins", "minute", "minutes":
		return time.Duration(n) * time.Minute, true
	case "h", "hr", "hrs", "hour", "hours":
		return time.Duration(n) * time.Hour, true
	case "d", "day", "days":
		return time.Duration(n) * 24 * time.Hour, true
	default:
		return 0, false
	}
}

type paste struct {
	Data    string `json:"data"`           // base64url(iv || AES-GCM ciphertext), encrypted in the browser
	Salt    string `json:"salt,omitempty"` // base64url PBKDF2 salt, present when passphrase-protected
	HL      bool   `json:"hl,omitempty"`   // syntax highlighting requested
	Burn    bool   `json:"burn"`           // delete after first fetch (immediately unless passphrase-protected)
	Expires int64  `json:"expires"`
	Len     int64  `json:"len,omitempty"` // blob sizes: ciphertext length; presence switches the reader to file mode
}

// envBytes parses a raw byte count (plain integer) with hard clamps.
func envBytes(name string, def, min, max int64) int64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < min || n > max {
		log.Fatalf("%s: bad value %q (want %d..%d bytes)", name, v, min, max)
	}
	return n
}

func main() {
	dataDir := flag.String("data", "data", "directory for stored ciphertexts")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	maxBlobBytes = envBytes("MAX_BLOB", maxBlobBytes, 1<<20, 64<<30)
	chunkBytes = envBytes("CHUNK", chunkBytes, 64<<10, 64<<20)
	if maxBlobBytes < chunkBytes {
		log.Fatal("MAX_BLOB below CHUNK")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	go janitor(*dataDir)

	// create-gate: presence of CREATE_KEY requires a bearer passphrase on POST
	// /api/paste. Reads and DELETEs stay open — the link is the capability.
	createKey := os.Getenv("CREATE_KEY")
	if createKey != "" {
		log.Print("zeropaste: create-gate enabled")
	}

	log.Printf("zeropaste: listening on http://%s (data dir %s, blob cap %d, chunk %d)", *addr, *dataDir, maxBlobBytes, chunkBytes)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           build(*dataDir, createKey),
		ReadHeaderTimeout: 10 * time.Second, // slowloris
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// graceful drain: finish in-flight creates on SIGTERM/SIGINT (docker stop)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = srv.ListenAndServe() }()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Print(err)
	}
}

func build(dir, createKey string) http.Handler {
	hf := func(fn func(http.ResponseWriter, *http.Request)) http.Handler { return http.HandlerFunc(fn) }
	rl := newLimiter(30) // pastes per IP per minute
	sess := newSessions(dir)
	owns := newShareIndex(dir, sess)
	cer := newCeremony()
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", secure(hf(healthz)))
	mux.Handle("GET /api/gate", secure(hf(gateStatus(createKey))))
	mux.Handle("POST /api/gate", secure(rl.guard(hf(gateVerify(createKey)))))
	mux.Handle("GET /", secure(hf(serveIndex)))
	mux.Handle("GET /p/", secure(hf(serveIndex))) // SPA route, id parsed client-side
	mux.Handle("POST /api/paste", secure(rl.guard(authGate(createKey, hf(create(dir, owns))))))
	mux.Handle("GET /api/paste/{id}", secure(hf(readAPI(dir))))
	mux.Handle("GET /api/paste/{id}/blob", secure(hf(readBlob(dir))))
	mux.Handle("DELETE /api/paste/{id}", secure(hf(deleteAPI(dir))))
	mux.Handle("POST /api/uploads", secure(rl.guard(authGate(createKey, hf(uploadInit(dir))))))
	mux.Handle("PUT /api/uploads/{id}/{n}", secure(authGate(createKey, hf(uploadChunk(dir)))))
	mux.Handle("DELETE /api/uploads/{id}", secure(hf(uploadAbort(dir))))
	mux.Handle("POST /api/uploads/{id}/finish", secure(rl.guard(authGate(createKey, hf(uploadFinish(dir, owns))))))
	mux.Handle("GET /assets/", secure(assets()))
	// phase-2 identity (passkeys) + active-share dashboard
	mux.Handle("GET /api/me", secure(hf(me(sess))))
	mux.Handle("POST /api/identity/register/begin", secure(rl.guard(hf(sess.registerBegin(cer)))))
	mux.Handle("POST /api/identity/register/finish", secure(rl.guard(hf(sess.registerFinish(cer, owns)))))
	mux.Handle("POST /api/identity/login/begin", secure(rl.guard(hf(sess.loginBegin(cer)))))
	mux.Handle("POST /api/identity/login/finish", secure(rl.guard(hf(sess.loginFinish(cer)))))
	mux.Handle("POST /api/identity/logout", secure(hf(sess.logout())))
	mux.Handle("GET /api/shares", secure(hf(owns.list())))
	return mux
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("ok"))
}

// gateStatus lets the client render the gate screen immediately instead of
// discovering the gate through a failed submit. Boolean only — never expose
// the key or a hint of it.
func gateStatus(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		respond(w, 200, map[string]bool{"enabled": key != ""})
	}
}

// gateVerify validates a candidate site passphrase (Bearer header) with 204 on
// success / 401 on failure — lets the client unlock its gate screen up front.
func gateVerify(key string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if key == "" || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")), []byte(key)) != 1 {
			httpError(w, 401, "authorization required")
			return
		}
		w.WriteHeader(204)
	}
}

// authGate checks Authorization: Bearer <key> in constant time when a key is
// configured; otherwise it is a pass-through.
func authGate(key string, next http.Handler) http.Handler {
	if key == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
			httpError(w, 401, "authorization required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// ponytail: in-memory fixed-window limiter, correct for this single process;
// back it with a shared store only if zeropaste ever runs as multiple replicas.
// X-Forwarded-For: the LAST entry is used — the single trusted reverse proxy
// in front appends the real client IP, so clients spoofing an earlier entry
// only pollute their own chain, never shift their bucket.
type limiter struct {
	mu    sync.Mutex
	hits  map[string]int
	limit int
	until time.Time
}

func newLimiter(limit int) *limiter {
	return &limiter{hits: make(map[string]int), limit: limit}
}

func (l *limiter) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ""
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if p := strings.TrimSpace(parts[i]); p != "" {
					ip = p
					break
				}
			}
		}
		if ip == "" {
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				ip = host
			} else {
				ip = r.RemoteAddr
			}
		}
		l.mu.Lock()
		now := time.Now()
		if now.After(l.until) {
			clear(l.hits)
			l.until = now.Add(time.Minute)
		}
		l.hits[ip]++
		ok := l.hits[ip] <= l.limit
		l.mu.Unlock()
		if !ok {
			httpError(w, 429, "too many pastes from your address, slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/p/") && !validID(r.URL.Path[len("/p/"):]) {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/p/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(indexHTML)
}

func assets() http.Handler {
	sub, err := fs.Sub(assetFS, "web/assets")
	if err != nil {
		log.Fatal(err)
	}
	// no directory listings, only known files
	return http.StripPrefix("/assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=86400")
		http.ServeFileFS(w, r, sub, r.URL.Path)
	}))
}

func create(dir string, owns *shareIndex) http.HandlerFunc {
	type req struct {
		Data string `json:"data"`
		Salt string `json:"salt"`
		TTL  string `json:"ttl"`
		HL   bool   `json:"hl"`
		Burn bool   `json:"burn"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		var req req
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, 400, "invalid request body")
			return
		}
		ttl, ok := parseTTL(req.TTL)
		if !ok {
			httpError(w, 400, "ttl must be a burn time like 10m, 6h or 1d (1 minute to 30 days)")
			return
		}
		if ttl < time.Minute || ttl > 30*24*time.Hour {
			httpError(w, 400, "ttl must be between 1 minute and 30 days")
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(req.Data)
		if err != nil || len(raw) < 12+16 { // iv + GCM tag minimum
			httpError(w, 400, "data must be base64url(iv || ciphertext)")
			return
		}
		if len(raw) > maxData {
			httpError(w, 400, "paste too large (64 KiB cap)")
			return
		}
		if req.Salt != "" {
			salt, err := base64.RawURLEncoding.DecodeString(req.Salt)
			if err != nil || len(salt) < 8 || len(salt) > 32 {
				httpError(w, 400, "salt must be 8-32 raw bytes, base64url")
				return
			}
		}
		b, _ := json.Marshal(paste{Data: req.Data, Salt: req.Salt, HL: req.HL, Burn: req.Burn, Expires: time.Now().Add(ttl).Unix()})
		id := newID(dir)
		if err := os.WriteFile(filepath.Join(dir, id+".json"), b, 0o600); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store paste")
			return
		}
		if owns != nil {
			owns.record(r, id) // dashboard row for signed-in creators
		}
		respond(w, 200, map[string]string{"id": id})
	}
}

func readAPI(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store") // keep ciphertext out of shared/local HTTP caches
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(dir, id+".json")
		b, err := os.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var p paste
		if json.Unmarshal(b, &p) != nil {
			http.NotFound(w, r)
			return
		}
		if p.Expires < time.Now().Unix() {
			os.Remove(path)
			os.Remove(filepath.Join(dir, strings.TrimSuffix(filepath.Base(path), ".json")+".blob"))
			http.NotFound(w, r)
			return
		}
		// ponytail: burn is read-then-delete; two racing readers can both
		// succeed. Fine for a friends-only box; make it create/rename-once
		// if stronger guarantees ever matter.
		//
		// Passphrase-protected pastes skip burn-on-read: a link unfurler or
		// wrong-passphrase visitor must not destroy the paste. The client
		// deletes via DELETE /api/paste/{id} after a successful decrypt.
		if p.Burn && p.Salt == "" {
			if p.Len > 0 {
				// ponytail: blob bundles can't be deleted per-range statelessly;
				// burn-on-read = short grace window for the actual reader to pull
				// chunks, then the janitor reaps. Ciphertext is unreadable without
				// the fragment key; a link unfurler sees none of it. Racing
				// readers share the window (same ceiling class as text burns).
				p.Expires = time.Now().Unix() - 1 + burnWindowSec // sweep treats `< now` strictly; start one second back
				if b, err := json.Marshal(p); err == nil {
					os.WriteFile(path, b, 0o600)
				}
			} else if err := os.Remove(path); err != nil {
				log.Print(err)
			}
		}
		out := map[string]any{"salt": p.Salt, "hl": p.HL, "burn": p.Burn, "expires": p.Expires}
		if p.Len > 0 {
			out["len"] = p.Len
		} else {
			out["data"] = p.Data
		}
		respond(w, 200, out)
	}
}

func deleteAPI(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		if err := os.Remove(filepath.Join(dir, id+".json")); err != nil && !os.IsNotExist(err) {
			httpError(w, 500, "delete failed")
			return
		}
		os.Remove(filepath.Join(dir, id+".blob")) // bundles die as a whole, burn flag or not
		respond(w, 200, map[string]bool{"ok": true})
	}
}

func janitor(dir string) {
	for range time.Tick(time.Minute) {
		sweep(dir)
	}
}

// sweep removes expired/aged state; shared by the janitor goroutine and tests.
func sweep(dir string) {
	now := time.Now().Unix()
	uploads := filepath.Join(dir, "uploads")
	if entries, err := os.ReadDir(uploads); err == nil {
		for _, e := range entries {
			name := e.Name()
			p := filepath.Join(uploads, name)
			// unfinished session cleanup: manifest gone, or init older than 2h
			if e.IsDir() {
				stale := true
				if b, err := os.ReadFile(filepath.Join(p, "upload.json")); err == nil {
					var u uprec
					if json.Unmarshal(b, &u) == nil && now-u.Created < 7200 {
						stale = false
					}
				}
				if stale {
					os.RemoveAll(p)
				}
				continue
			}
			os.Remove(p) // *.burn-style leftovers in the uploads dir
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".burn") {
			os.Remove(filepath.Join(dir, name)) // leftovers from crashed burn reads
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var p paste
		if json.Unmarshal(b, &p) == nil && p.Expires < now {
			os.Remove(filepath.Join(dir, name))
			os.Remove(filepath.Join(dir, strings.TrimSuffix(name, ".json")+".blob"))
		}
	}
}

// uprec is an upload session manifest: enough to assemble, nothing more.
type uprec struct {
	Len     int64  `json:"len"`
	TTL     string `json:"ttl"`
	Salt    string `json:"salt,omitempty"`
	Burn    bool   `json:"burn"`
	Created int64  `json:"created"`
}

func chunksFor(total, chunk int64) int64 {
	return (total + chunk - 1) / chunk
}

// uploadInit creates an upload session: uploads/<id>/ holds the manifest and
// one file per chunk. Body-session ids share paste-id secrecy (capability).
func uploadInit(dir string) http.HandlerFunc {
	type req struct {
		Len  int64  `json:"len"`
		TTL  string `json:"ttl"`
		Salt string `json:"salt"`
		Burn bool   `json:"burn"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
		var req req
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, 400, "invalid request body")
			return
		}
		if _, ok := parseTTL(req.TTL); !ok {
			httpError(w, 400, "ttl must be a burn time like 10m, 6h or 1d (1 minute to 30 days)")
			return
		}
		if req.Salt != "" {
			salt, err := base64.RawURLEncoding.DecodeString(req.Salt)
			if err != nil || len(salt) < 8 || len(salt) > 32 {
				httpError(w, 400, "salt must be 8-32 raw bytes, base64url")
				return
			}
		}
		if req.Len < 1 || req.Len > maxBlobBytes {
			httpError(w, 400, "blob size out of range")
			return
		}
		uploads := filepath.Join(dir, "uploads")
		if err := os.MkdirAll(uploads, 0o700); err != nil {
			log.Print(err)
			httpError(w, 500, "could not open upload area")
			return
		}
		id := newUploadID(uploads)
		rd := filepath.Join(uploads, id)
		if err := os.Mkdir(rd, 0o700); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store upload")
			return
		}
		b, _ := json.Marshal(uprec{Len: req.Len, TTL: req.TTL, Salt: req.Salt, Burn: req.Burn, Created: time.Now().Unix()})
		if err := os.WriteFile(filepath.Join(rd, "upload.json"), b, 0o600); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store upload")
			return
		}
		respond(w, 200, map[string]any{"id": id, "chunkSize": chunkBytes, "chunks": chunksFor(req.Len, chunkBytes)})
	}
}

func newUploadID(uploads string) string { // same retry contract as newID, scoped to the uploads dir
	for {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		id := base64.RawURLEncoding.EncodeToString(b)
		if _, err := os.Stat(filepath.Join(uploads, id)); os.IsNotExist(err) {
			return id
		}
	}
}

// uploadChunk stores one ciphertext chunk; repeated PUT = resume (overwrite).
func uploadChunk(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		rd := filepath.Join(dir, "uploads", id)
		b, err := os.ReadFile(filepath.Join(rd, "upload.json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var u uprec
		if json.Unmarshal(b, &u) != nil {
			http.NotFound(w, r)
			return
		}
		n, err := strconv.Atoi(r.PathValue("n"))
		if err != nil || n < 0 || n >= int(chunksFor(u.Len, chunkBytes)) {
			httpError(w, 400, "bad chunk index")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, chunkBytes+1)
		part, err := io.ReadAll(r.Body)
		if err != nil || int64(len(part)) < 1 || int64(len(part)) > chunkBytes {
			httpError(w, 400, "chunk size out of range")
			return
		}
		if err := os.WriteFile(filepath.Join(rd, fmt.Sprintf("%d.part", n)), part, 0o600); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store chunk")
			return
		}
		w.WriteHeader(204)
	}
}

func uploadAbort(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		os.RemoveAll(filepath.Join(dir, "uploads", id))
		respond(w, 200, map[string]bool{"ok": true})
	}
}

// uploadFinish verifies the chunk set, joins it, promotes to a paste.
func uploadFinish(dir string, owns *shareIndex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		if _, err := os.Stat(filepath.Join(dir, id+".json")); err == nil {
			respond(w, 200, map[string]string{"id": id}) // idempotent double finish
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, "uploads", id, "upload.json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var u uprec
		if json.Unmarshal(b, &u) != nil {
			http.NotFound(w, r)
			return
		}
		rd := filepath.Join(dir, "uploads", id)
		chunks := chunksFor(u.Len, chunkBytes)
		blob, err := os.OpenFile(filepath.Join(dir, id+".blob"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Print(err)
			httpError(w, 500, "could not store paste")
			return
		}
		ok := true
		sizes := make([]int64, 0, chunks)
		for n := int64(0); n < chunks; n++ {
			st, err := os.Stat(filepath.Join(rd, fmt.Sprintf("%d.part", n)))
			if err != nil {
				ok = false
				break
			}
			want := chunkBytes
			if n == chunks-1 {
				want = u.Len - (chunks-1)*chunkBytes
			}
			if st.Size() != want {
				ok = false
				break
			}
			sizes = append(sizes, st.Size())
		}
		if ok {
			for n, size := range sizes {
				f, err := os.Open(filepath.Join(rd, fmt.Sprintf("%d.part", n)))
				if err != nil {
					ok = false
					break
				}
				cp, err := io.CopyN(blob, f, size)
				f.Close()
				if err != nil || cp != size {
					ok = false
					break
				}
			}
		}
		blob.Close()
		if !ok {
			os.Remove(filepath.Join(dir, id+".blob")) // parts stay for retry
			httpError(w, 400, "upload incomplete or chunk sizes off")
			return
		}
		ttl, _ := parseTTL(u.TTL)
		pb, _ := json.Marshal(paste{Len: u.Len, Salt: u.Salt, Burn: u.Burn, Expires: time.Now().Add(ttl).Unix()})
		if err := os.WriteFile(filepath.Join(dir, id+".json"), pb, 0o600); err != nil {
			os.Remove(filepath.Join(dir, id+".blob"))
			log.Print(err)
			httpError(w, 500, "could not store paste")
			return
		}
		os.RemoveAll(rd)
		if owns != nil {
			owns.record(r, id) // dashboard row for signed-in creators
		}
		respond(w, 200, map[string]string{"id": id})
	}
}

// readBlob serves ciphertext ranges for bundle pastes.
func readBlob(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("id")
		if !validID(id) {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, id+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		var p paste
		if json.Unmarshal(b, &p) != nil || p.Len <= 0 {
			http.NotFound(w, r)
			return
		}
		if p.Expires < time.Now().Unix() {
			os.Remove(filepath.Join(dir, id+".json"))
			os.Remove(filepath.Join(dir, id+".blob"))
			http.NotFound(w, r)
			return
		}
		offset, errL := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if errL != nil || offset < 0 || offset >= p.Len {
			httpError(w, 400, "bad offset")
			return
		}
		length := p.Len - offset
		if length > chunkBytes {
			length = chunkBytes
		}
		f, err := os.Open(filepath.Join(dir, id+".blob"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		if _, err := io.CopyN(w, io.NewSectionReader(f, offset, length), length); err != nil {
			log.Print(err)
			return
		}
	}
}

var idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func validID(id string) bool {
	if len(id) < 8 || len(id) > 16 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune(idAlphabet, c) {
			return false
		}
	}
	return true
}

func newID(dir string) string {
	for {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		id := base64.RawURLEncoding.EncodeToString(b)
		if _, err := os.Stat(filepath.Join(dir, id+".json")); os.IsNotExist(err) {
			return id
		}
	}
}

func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}

// ---- phase 2: passkey identity (go-webauthn), signed-cookie sessions, ----
// ---- and the active-shares dashboard. Storage stays file-shaped:      ----
// ---- identities/<id>.json, shares/<ident>/<paste>.json; the HMAC      ----
// ---- session token lives on the client cookie, nothing on disk.       ----

const sessionCookie = "zp.session"
const sessionTTL = 30 * 24 * time.Hour

type identity struct {
	ID    string                `json:"id"` // b64url of 16 random bytes
	Name  string                `json:"name,omitempty"`
	Creds []webauthn.Credential `json:"creds"`
}

func (i *identity) WebAuthnID() []byte {
	d, _ := base64.RawURLEncoding.DecodeString(i.ID)
	return d
}
func (i *identity) WebAuthnName() string        { return i.Name }
func (i *identity) WebAuthnDisplayName() string { return i.Name }
func (i *identity) WebAuthnIcon() string        { return "" }
func (i *identity) WebAuthnCredentials() []webauthn.Credential {
	return i.Creds
}

// sessions: HMAC-signed stateless cookie; the only server secret is
// <dir>/.session.key (auto-generated once, 0600).
type sessions struct {
	dir    string
	secret []byte
}

func newSessions(dir string) *sessions {
	keyPath := filepath.Join(dir, ".session.key")
	secret, err := os.ReadFile(keyPath)
	if err != nil || len(secret) != 32 {
		if os.Getenv("SESSION_SECRET") != "" {
			secret = []byte(os.Getenv("SESSION_SECRET"))
		} else {
			secret = make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				log.Fatal(err)
			}
		}
		if err := os.WriteFile(keyPath, secret, 0o600); err != nil {
			log.Fatal(err)
		}
	}
	return &sessions{dir: dir, secret: secret}
}

type sessionClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

func (s *sessions) sign(c sessionClaims) string {
	b, _ := json.Marshal(c)
	payload := base64.RawURLEncoding.EncodeToString(b)
	mac := hmacSHA256(s.secret, []byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac)
}

func (s *sessions) verify(tok string) (sessionClaims, bool) {
	var zero sessionClaims
	payload, sig, found := strings.Cut(tok, ".")
	if !found {
		return zero, false
	}
	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmacEqual(hmacSHA256(s.secret, []byte(payload)), want) {
		return zero, false
	}
	var c sessionClaims
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, &c) != nil {
		return zero, false
	}
	return c, c.Exp > time.Now().Unix()
}

// identFrom returns the logged-in identity for a request, or nil.
func (s *sessions) identFrom(r *http.Request) *identity {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	claims, ok := s.verify(c.Value)
	if !ok {
		return nil
	}
	return loadIdentity(filepath.Join(s.dir, "identities"), claims.Sub)
}

func loadIdentity(idents string, id string) *identity {
	if id == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(idents, id+".json"))
	if err != nil {
		return nil
	}
	var i identity
	if json.Unmarshal(b, &i) != nil {
		return nil
	}
	return &i
}

func (s *sessions) saveIdentity(i *identity) error {
	idents := filepath.Join(s.dir, "identities")
	if err := os.MkdirAll(idents, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(i)
	return os.WriteFile(filepath.Join(idents, i.ID+".json"), b, 0o600)
}

// findIdentityByCred scans the (small) identity dir for a credential id.
func findIdentityByCred(idents string, credID []byte) *identity {
	entries, err := os.ReadDir(idents)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		i, err := os.ReadFile(filepath.Join(idents, e.Name()))
		if err != nil {
			continue
		}
		var ident identity
		if json.Unmarshal(i, &ident) != nil {
			continue
		}
		for _, c := range ident.Creds {
			if bytes.Equal(c.ID, credID) {
				return &ident
			}
		}
	}
	return nil
}

func (s *sessions) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *sessions) issue(w http.ResponseWriter, id string) {
	tok := s.sign(sessionClaims{Sub: id, Exp: time.Now().Add(sessionTTL).Unix()})
	s.setCookie(w, tok, int(sessionTTL/time.Second))
}

// -- handlers --

func me(s *sessions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i := s.identFrom(r)
		if i == nil {
			respond(w, 200, map[string]any{"name": "", "open": registrationOpen()})
			return
		}
		respond(w, 200, map[string]any{"name": i.Name, "id": i.ID, "open": registrationOpen()})
	}
}

func (s *sessions) logout() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		s.setCookie(w, "", -1)
		respond(w, 200, map[string]bool{"ok": true})
	}
}

func hmacSHA256(secret, data []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(data)
	return m.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// ceremony: holds in-flight webauthn register/login states in memory
// (single-instance design mandate; server restart drops pending ceremonies).
type ceremony struct {
	mu  sync.Mutex
	reg map[string]webauthn.SessionData
	log map[string]webauthn.SessionData
	// pending ceremony identity users (registration path); identity files
	// are written only when finish succeeds.
	tokens map[string]*identity
}

func newCeremony() *ceremony {
	return &ceremony{
		reg:    map[string]webauthn.SessionData{},
		log:    map[string]webauthn.SessionData{},
		tokens: map[string]*identity{},
	}
}

func (c *ceremony) pending(id string) (*identity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.tokens[id]
	delete(c.tokens, id)
	return u, ok
}

func (c *ceremony) setPending(id string, u *identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[id] = u
}

func (c *ceremony) putReg(id string, s webauthn.SessionData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reg[id] = s
}
func (c *ceremony) getReg(id string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.reg[id]
	if ok {
		delete(c.reg, id)
	}
	return s, ok
}
func (c *ceremony) putLog(id string, s webauthn.SessionData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log[id] = s
}
func (c *ceremony) getLog(id string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.log[id]
	if ok {
		delete(c.log, id)
	}
	return s, ok
}

// rpFromRequest derives the webauthn config from the request: RPID = host
// (no port), origin = scheme + host. Both schemes are allowed because the
// proxy in front may or may not forward X-Forwarded-Proto; the RPID pin is
// what protects the ceremony, not the scheme string.
func rpFromRequest(r *http.Request) *webauthn.WebAuthn {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "zeropaste",
		RPOrigins:     []string{"https://" + host, "http://" + host},
	})
	if err != nil {
		return nil
	}
	return w
}

func continueJSON(w http.ResponseWriter, r *http.Request) (string, bool) {
	type body struct {
		SessionID string `json:"sessionId"`
	}
	var b body
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpError(w, 400, "invalid request body")
		return "", false
	}
	return b.SessionID, true
}

func (s *sessions) registerBegin(c *ceremony) http.HandlerFunc {
	type req struct {
		Name string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !registrationOpen() && s.identFrom(r) == nil {
			httpError(w, 403, "passkey registration is closed on this instance")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
		var q req
		_ = json.NewDecoder(r.Body).Decode(&q) // name optional; anonymous register allowed
		wa := rpFromRequest(r)
		if wa == nil {
			httpError(w, 500, "ceremony failed")
			return
		}
		existing := s.identFrom(r)
		var user identity
		id := newSessionID()
		if existing != nil {
			user = *existing // attach another passkey to this identity
		} else {
			name := q.Name
			if strings.TrimSpace(name) == "" {
				name = "friend"
			}
			user = identity{ID: newSessionID(), Name: name}
		}
		creation, sd, err := wa.BeginRegistration(&user)
		if err != nil {
			log.Print(err)
			httpError(w, 500, "ceremony failed")
			return
		}
		c.putReg(id, *sd)
		c.setPending(id, &user) // the pending identity rides in memory; not yet on disk
		respond(w, 200, map[string]any{"options": creation, "sessionId": id, "name": user.Name})
	}
}

func (s *sessions) registerFinish(c *ceremony, owns *shareIndex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, ok := continueJSON(w, r)
		if !ok {
			return
		}
		sd, found := c.getReg(sid)
		if !found {
			httpError(w, 400, "unknown session")
			return
		}
		wa := rpFromRequest(r)
		if wa == nil {
			httpError(w, 500, "ceremony failed")
			return
		}
		user, ok := c.pending(sid)
		if !ok {
			httpError(w, 400, "unknown session")
			return
		}
		cred, err := wa.FinishRegistration(user, sd, r)
		if err != nil {
			log.Print(err)
			httpError(w, 400, "registration failed")
			return
		}
		user.Creds = append(user.Creds, *cred)
		if err := s.saveIdentity(user); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store identity")
			return
		}
		if owns != nil {
			owns.attach(user.ID)
		}
		s.issue(w, user.ID)
		respond(w, 200, map[string]any{"name": user.Name})
	}
}

func (s *sessions) loginBegin(c *ceremony) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// discoverable credentials: no user hint; identity resolved from the
		// returned credential. Allowlist = every stored credential id.
		wa := rpFromRequest(r)
		if wa == nil {
			httpError(w, 500, "ceremony failed")
			return
		}
		allow := [][]byte{}
		for _, i := range listIdentities(filepath.Join(s.dir, "identities")) {
			for _, c := range i.Creds {
				allow = append(allow, c.ID)
			}
		}
		sd := webauthn.SessionData{
			Challenge:            newSessionID(),
			RelyingPartyID:       wa.Config.RPID,
			AllowedCredentialIDs: allow,
			Expires:              time.Now().Add(2 * time.Minute),
			UserVerification:     "preferred",
		}
		responseBody := map[string]any{
			"publicKey": map[string]any{
				"challenge":        base64.RawURLEncoding.EncodeToString([]byte(sd.Challenge)),
				"rpId":             wa.Config.RPID,
				"timeout":          60000,
				"userVerification": "preferred",
			},
		}
		token := newSessionID()
		c.putLog(token, sd)
		respond(w, 200, map[string]any{"options": responseBody, "sessionId": token})
	}
}

func (s *sessions) loginFinish(c *ceremony) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, ok := continueJSON(w, r)
		if !ok {
			return
		}
		sd, found := c.getLog(sid)
		if !found {
			httpError(w, 400, "unknown session")
			return
		}
		wa := rpFromRequest(r)
		if wa == nil {
			httpError(w, 500, "ceremony failed")
			return
		}
		parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
		if err != nil {
			httpError(w, 400, "invalid login response")
			return
		}
		credID := credIDBytes(parsed.Response.UserHandle)
		if len(credID) == 0 {
			credID = credIDBytes(parsed.ID)
		}
		ident := findIdentityByCred(filepath.Join(s.dir, "identities"), credID)
		if ident == nil {
			httpError(w, 401, "unknown passkey")
			return
		}
		updated, err := wa.ValidateLogin(ident, sd, parsed)
		if err != nil {
			log.Print(err)
			httpError(w, 401, "login failed")
			return
		}
		// update the stored credential (sign counters, transports)
		for idx := range ident.Creds {
			if bytes.Equal(ident.Creds[idx].ID, updated.ID) {
				ident.Creds[idx] = *updated
			}
		}
		if err := s.saveIdentity(ident); err != nil {
			log.Print(err)
			httpError(w, 500, "could not store identity")
			return
		}
		s.issue(w, ident.ID)
		respond(w, 200, map[string]any{"name": ident.Name})
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func credIDBytes(v any) []byte {
	switch t := v.(type) {
	case []byte:
		return t
	case string:
		d, _ := base64.RawURLEncoding.DecodeString(t)
		return d
	}
	return nil
}

// listIdentities returns all stored identities (small friend-group store).
func listIdentities(idents string) []*identity {
	entries, err := os.ReadDir(idents)
	if err != nil {
		return nil
	}
	var out []*identity
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(idents, e.Name()))
		if err != nil {
			continue
		}
		var i identity
		if json.Unmarshal(b, &i) == nil {
			out = append(out, &i)
		}
	}
	return out
}

// shareIndex: per-identity directory of share ownership rows; listing is
// computed live from the actual paste metas (expired pastes self-prune).
type shareIndex struct {
	dir  string
	sess *sessions
}

func newShareIndex(dir string, sess *sessions) *shareIndex {
	return &shareIndex{dir: dir, sess: sess}
}

func (si *shareIndex) idents(suite string) string {
	return filepath.Join(si.dir, "shares", suite)
}

// attach after a fresh registration makes previously created anon impossible;
// rows only accrue from creation while logged in.
func (si *shareIndex) attach(identID string) {}

// record writes an ownership row at create/finish time (no-op when anon).
func (si *shareIndex) record(r *http.Request, pasteID string) {
	i := si.sess.identFrom(r)
	if i == nil {
		return
	}
	dir := si.idents(i.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(map[string]any{"created": time.Now().Unix()})
	_ = os.WriteFile(filepath.Join(dir, pasteID+".json"), b, 0o600)
}

func (si *shareIndex) list() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		i := si.sess.identFrom(r)
		if i == nil {
			respond(w, 200, []any{})
			return
		}
		dir := si.idents(i.ID)
		entries, err := os.ReadDir(dir)
		if err != nil {
			respond(w, 200, []any{})
			return
		}
		out := []any{}
		for _, e := range entries {
			name := strings.TrimSuffix(e.Name(), ".json")
			b, err := os.ReadFile(filepath.Join(si.dir, name+".json"))
			if err != nil {
				os.Remove(filepath.Join(dir, e.Name())) // expired pastes self-prune
				continue
			}
			var p paste
			if json.Unmarshal(b, &p) != nil || p.Expires < time.Now().Unix() {
				os.Remove(filepath.Join(dir, e.Name())) // expired file or corrupt row
				continue
			}
			kind := "text"
			if p.Len > 0 {
				kind = "bundle"
			}
			out = append(out, map[string]any{"id": name, "kind": kind, "burn": p.Burn, "expires": p.Expires})
		}
		respond(w, 200, out)
	}
}

// registrationOpen: server-wide switch for NEW identity registrations
// (REG_OPEN env; default true). Subjects with an existing session can always
// attach more passkeys - closing registration only locks fresh accounts.
func registrationOpen() bool {
	v := strings.TrimSpace(os.Getenv("REG_OPEN"))
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		log.Fatalf("REG_OPEN: %q invalid, want true/false", v)
	}
	return b
}
