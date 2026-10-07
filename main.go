// zeropaste — zero-knowledge paste sharing in a single binary.
// Server stores only ciphertext; the AES-256-GCM key lives in the URL fragment.
package main

import (
	"context"
	"crypto/rand"
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
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", secure(hf(healthz)))
	mux.Handle("GET /api/gate", secure(hf(gateStatus(createKey))))
	mux.Handle("POST /api/gate", secure(rl.guard(hf(gateVerify(createKey)))))
	mux.Handle("GET /", secure(hf(serveIndex)))
	mux.Handle("GET /p/", secure(hf(serveIndex))) // SPA route, id parsed client-side
	mux.Handle("POST /api/paste", secure(rl.guard(authGate(createKey, hf(create(dir))))))
	mux.Handle("GET /api/paste/{id}", secure(hf(readAPI(dir))))
	mux.Handle("GET /api/paste/{id}/blob", secure(hf(readBlob(dir))))
	mux.Handle("DELETE /api/paste/{id}", secure(hf(deleteAPI(dir))))
	mux.Handle("POST /api/uploads", secure(rl.guard(authGate(createKey, hf(uploadInit(dir))))))
	mux.Handle("PUT /api/uploads/{id}/{n}", secure(authGate(createKey, hf(uploadChunk(dir)))))
	mux.Handle("DELETE /api/uploads/{id}", secure(hf(uploadAbort(dir))))
	mux.Handle("POST /api/uploads/{id}/finish", secure(rl.guard(authGate(createKey, hf(uploadFinish(dir))))))
	mux.Handle("GET /assets/", secure(assets()))
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

func create(dir string) http.HandlerFunc {
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
func uploadFinish(dir string) http.HandlerFunc {
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
