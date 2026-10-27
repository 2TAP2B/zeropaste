package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(build(t.TempDir(), ""))
	t.Cleanup(s.Close)
	return s
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	h.ServeHTTP(rec, req)
	return rec
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func fakePayload() string {
	// minimum shape: 12-byte IV + 16-byte GCM tag
	return base64.RawURLEncoding.EncodeToString(make([]byte, 28))
}

func TestRoundTrip(t *testing.T) {
	h := build(t.TempDir(), "")
	rec := post(t, h, fmt.Sprintf(`{"data":%q,"ttl":"1d","burn":false}`, fakePayload()))
	if rec.Code != 200 {
		t.Fatalf("create: got %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &created) != nil || created.ID == "" {
		t.Fatalf("no id returned: %s", rec.Body)
	}
	rec = get(h, "/api/paste/"+created.ID)
	var out struct {
		Data    string `json:"data"`
		Burn    bool   `json:"burn"`
		Expires int64  `json:"expires"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Data != fakePayload() || out.Burn || out.Expires == 0 {
		t.Fatalf("read: got %d %+v", rec.Code, out)
	}
}

func TestBurnAfterRead(t *testing.T) {
	h := build(t.TempDir(), "")
	rec := post(t, h, fmt.Sprintf(`{"data":%q,"ttl":"1d","burn":true}`, fakePayload()))
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if rec := get(h, "/api/paste/"+created.ID); rec.Code != 200 {
		t.Fatalf("first read: got %d", rec.Code)
	}
	if rec := get(h, "/api/paste/"+created.ID); rec.Code != 404 {
		t.Fatalf("second read after burn: got %d, want 404", rec.Code)
	}
}

func TestExpiredPaste404s(t *testing.T) {
	dir := t.TempDir()
	h := build(dir, "")
	rec := post(t, h, fmt.Sprintf(`{"data":%q,"ttl":"1h","burn":false}`, fakePayload()))
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// rewind expiry directly in the store
	b, _ := json.Marshal(paste{Data: fakePayload(), Expires: time.Now().Add(-time.Minute).Unix()})
	if err := os.WriteFile(filepath.Join(dir, created.ID+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := get(h, "/api/paste/"+created.ID); rec.Code != 404 {
		t.Fatalf("expired read: got %d, want 404", rec.Code)
	}
	// swept: file gone
	if _, err := os.Stat(filepath.Join(dir, created.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("expired file not removed on read")
	}
}

func TestParseTTL(t *testing.T) {
	valid := map[string]time.Duration{
		"1h": time.Hour, "10 min": 10 * time.Minute, "10min": 10 * time.Minute,
		"6H": 6 * time.Hour, "1d": 24 * time.Hour, "30 days": 30 * 24 * time.Hour,
		"5m": 5 * time.Minute,
	}
	for in, want := range valid {
		got, ok := parseTTL(in)
		if !ok || got != want {
			t.Fatalf("parseTTL(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", "0d", "1w", "1h30m", "-5m", "5", "min"} {
		if _, ok := parseTTL(in); ok {
			t.Fatalf("parseTTL(%q) should fail", in)
		}
	}
}

func TestBadRequests(t *testing.T) {
	h := build(t.TempDir(), "")
	cases := []string{
		`{"data":"a","ttl":"1d"}`,                                         // too short to be iv||ct
		fmt.Sprintf(`{"data":%q,"ttl":"2w"}`, fakePayload()),              // bad ttl
		fmt.Sprintf(`{"data":%q,"ttl":"31d"}`, fakePayload()),             // over 30-day ceiling
		fmt.Sprintf(`{"data":%q,"ttl":""}`, fakePayload()),                // empty ttl
		`{"data":"not-base64!!","ttl":"1d"}`,                              // undecodable
		fmt.Sprintf(`{"data":%q,"salt":"!!!","ttl":"1d"}`, fakePayload()), // bad salt
	}
	for _, body := range cases {
		if rec := post(t, h, body); rec.Code != 400 {
			t.Fatalf("bad request %q: got %d, want 400", body, rec.Code)
		}
	}
}

func TestHealthz(t *testing.T) {
	h := build(t.TempDir(), "")
	if rec := get(h, "/healthz"); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("healthz: got %d %q", rec.Code, rec.Body)
	}
}

func TestGateStatus(t *testing.T) {
	open := build(t.TempDir(), "")
	rec := get(open, "/api/gate")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("open gate: got %d %s", rec.Code, rec.Body)
	}
	gated := build(t.TempDir(), "secret")
	rec = get(gated, "/api/gate")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("gated: got %d %s", rec.Code, rec.Body)
	}
}

func TestAuthGate(t *testing.T) {
	h := build(t.TempDir(), "friend-passphrase")
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())

	// abuse case: reader (or anyone) must still READ without the gate
	rec := post(t, h, body) // no header
	if rec.Code != 401 {
		t.Fatalf("create without key: got %d, want 401", rec.Code)
	}

	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 401 {
		t.Fatalf("create with wrong key: got %d, want 401", rec2.Code)
	}

	req3 := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	req3.Header.Set("Authorization", "Bearer friend-passphrase")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != 200 {
		t.Fatalf("create with correct key: got %d, want 200", rec3.Code)
	}

	// the created paste readable with no auth at all
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec3.Body.Bytes(), &created)
	if created.ID == "" || get(h, "/api/paste/"+created.ID).Code != 200 {
		t.Fatal("paste created with gate key is not publicly readable")
	}
	if rec := get(h, "/healthz"); rec.Code != 200 {
		t.Fatal("healthz must stay open behind the gate")
	}
}

func TestPassphrasePaste(t *testing.T) {
	h := build(t.TempDir(), "")
	salt := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	rec := post(t, h, fmt.Sprintf(`{"data":%q,"salt":%q,"ttl":"1d","burn":true,"hl":true}`, fakePayload(), salt))
	if rec.Code != 200 {
		t.Fatalf("create: got %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// wrong visitor (or unfurler) must NOT destroy a passphrase-protected burn paste
	if rec := get(h, "/api/paste/"+created.ID); rec.Code != 200 {
		t.Fatalf("first read: got %d", rec.Code)
	}
	var out struct {
		Salt string `json:"salt"`
		HL   bool   `json:"hl"`
		Burn bool   `json:"burn"`
	}
	json.Unmarshal(get(h, "/api/paste/"+created.ID).Body.Bytes(), &out)
	if out.Salt != salt || !out.HL || !out.Burn {
		t.Fatalf("metadata echo wrong: %+v", out)
	}

	// client deletes after successful decrypt
	req := httptest.NewRequest("DELETE", "/api/paste/"+created.ID, nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 200 {
		t.Fatalf("delete: got %d", rec2.Code)
	}
	if rec := get(h, "/api/paste/"+created.ID); rec.Code != 404 {
		t.Fatalf("after delete: got %d, want 404", rec.Code)
	}
}

func TestAssetsServed(t *testing.T) {
	h := build(t.TempDir(), "")
	rec := get(h, "/assets/highlight.min.js")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Highlight.js") {
		t.Fatalf("assets: got %d", rec.Code)
	}
	if rec := get(h, "/assets/"); rec.Code != 404 {
		t.Fatalf("asset dir listing: got %d, want 404", rec.Code)
	}
	// pwa assets: explicit mime types (scratch has no /etc/mime.types) and
	// sw.js scoped to the whole origin, always revalidated on deploy
	for file, ctype := range map[string]string{
		"icon.svg":             "image/svg+xml",
		"manifest.webmanifest": "application/manifest+json",
		"og.png":               "image/png",
	} {
		if rec := get(h, "/assets/"+file); rec.Code != 200 {
			t.Fatalf("%s: got %d, want 200", file, rec.Code)
		} else if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, ctype) {
			t.Fatalf("%s: content type %q, want %s", file, got, ctype)
		}
	}
	rec = get(h, "/assets/sw.js")
	if rec.Code != 200 {
		t.Fatalf("sw.js: got %d, want 200", rec.Code)
	}
	if allowed := rec.Header().Get("Service-Worker-Allowed"); allowed != "/" {
		t.Fatalf("sw.js: Service-Worker-Allowed %q, want /", allowed)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("sw.js: cache control %q, want no-cache", cc)
	}
}

func TestRateLimit(t *testing.T) {
	h := build(t.TempDir(), "")
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())
	// abuse case: POST flood filling the disk - 30/min/IP, then 429
	for i := 0; i < 30; i++ {
		if rec := post(t, h, body); rec.Code != 200 {
			t.Fatalf("post %d: got %d, want 200", i+1, rec.Code)
		}
	}
	if rec := post(t, h, body); rec.Code != 429 {
		t.Fatalf("post 31: got %d, want 429", rec.Code)
	}
}

func TestPathValueAbuse(t *testing.T) {
	h := build(t.TempDir(), "")
	for _, path := range []string{
		"/api/paste/abcdefgh..", // dot traversal attempt - alphabet check must reject
		"/api/paste/abcd!!",
		"/api/paste/ab", // too short
	} {
		if rec := get(h, path); rec.Code != 404 {
			t.Fatalf("GET %q: got %d, want 404", path, rec.Code)
		}
	}
	// DELETE must not follow escape attempts either
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/paste/abcd!!", nil))
	if rec.Code != 404 {
		t.Fatalf("DELETE bad id: got %d, want 404", rec.Code)
	}
}

// Telegram (and other scrapers) reject relative og:image; the index must ship
// absolute preview URLs derived from the request. abuse case: a crafted Host
// header only shapes a meta tag on the attacker's own request.
func TestOgPreviewURLs(t *testing.T) {
	h := build(t.TempDir(), "")
	rec := get(h, "/")
	body := rec.Body.String()
	if !strings.Contains(body, `content="http://example.com/assets/og.png"`) {
		t.Fatal("og:image not absolute for the request host")
	}
	if strings.Contains(body, `content="/assets/og.png"`) {
		t.Fatal("relative og:image survived the rewrite")
	}
	if !strings.Contains(body, `<meta property="og:url" content="http://example.com/">`) {
		t.Fatal("og:url missing or not absolute")
	}
	// behind a TLS-terminating proxy the derived origin must be https
	req := httptest.NewRequest("GET", "/p/abcdefghijk", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, `content="https://example.com/assets/og.png"`) {
		t.Fatal("og:image not https behind X-Forwarded-Proto")
	}
	if !strings.Contains(body, `content="https://example.com/p/abcdefghijk"`) {
		t.Fatal("og:url does not carry the paste path")
	}
}

func TestIndexServed(t *testing.T) {
	h := build(t.TempDir(), "")
	for _, path := range []string{"/", "/p/whatever"} {
		rec := get(h, path)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "zero-knowledge") {
			t.Fatalf("GET %s: got %d, want embedded page", path, rec.Code)
		}
	}
	if rec := get(h, "/nope"); rec.Code != 404 {
		t.Fatalf("unknown path: got %d, want 404", rec.Code)
	}
}

// the footer carries the installed version: docker/nix builds stamp
// -X main.version, plain source builds fall back to the VCS tag/revision
// git bakes into buildinfo
func TestFooterVersion(t *testing.T) {
	ver0, foot0 := version, footVer
	version, footVer = "v9.9.9-test", ""
	h := build(t.TempDir(), "")
	rec := get(h, "/p/whatever")   // every SPA route renders the footer
	version, footVer = ver0, foot0 // restored before any other test can read it
	m := regexp.MustCompile(`id="footver">([^<]*)<`).FindStringSubmatch(rec.Body.String())
	if m == nil || m[1] != "v9.9.9-test" {
		t.Fatalf("stamped footer version: got %v", m)
	}
}

// unstamped (plain `go build` in a git tree): the built-in fallback must
// surface the VCS tag, the short revision, or dev - never leave the
// placeholder text or an empty chip
func TestFooterVersionFallback(t *testing.T) {
	ver0, foot0 := version, footVer
	version, footVer = "", ""
	h := build(t.TempDir(), "")
	rec := get(h, "/")
	version, footVer = ver0, foot0
	m := regexp.MustCompile(`id="footver">([^<]*)<`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("footer version span missing entirely")
	}
	format := regexp.MustCompile(`^(v\d+\.\d+\.\d+|[0-9a-f]{7}|dev)$`).MatchString
	if !format(m[1]) {
		t.Fatalf("footer version %q matches neither tag, revision, nor dev", m[1])
	}
}

// --- file uploads ---

func put(t *testing.T, h http.Handler, path string, body []byte, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", path, bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postTo(t *testing.T, h http.Handler, path, body, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// small chunk caps make chunk tests tiny and exact
func tinyChunks(t *testing.T) {
	t.Helper()
	oldBlob, oldChunk, oldWin := maxBlobBytes, chunkBytes, burnWindowSec
	maxBlobBytes, chunkBytes, burnWindowSec = 64, 8, 2
	t.Cleanup(func() { maxBlobBytes, chunkBytes, burnWindowSec = oldBlob, oldChunk, oldWin })
}

func initUpload(t *testing.T, h http.Handler, body string) (struct {
	ID       string `json:"id"`
	Chunks   int64  `json:"chunks"`
	ChunkSze int64  `json:"chunkSize"`
}, *httptest.ResponseRecorder) {
	t.Helper()
	var out struct {
		ID       string `json:"id"`
		Chunks   int64  `json:"chunks"`
		ChunkSze int64  `json:"chunkSize"`
	}
	rec := postTo(t, h, "/api/uploads", body, "")
	if rec.Code == 200 {
		if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.ID == "" {
			t.Fatalf("init: no id: %s", rec.Body)
		}
	}
	return out, rec
}

// --- public pastes: opt-in plaintext lane, accounts-only, PUBLIC_PASTES switch ---

// postAs: POST with a session cookie (the public surface is accounts-only)
func postAs(t *testing.T, h http.Handler, path, body, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if cookie != "" {
		req.Header.Add("Cookie", cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPublicPaste(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	// signed-in public create: plaintext stored verbatim, flag echoed
	rec := postAs(t, h, "/api/paste", `{"data":"hello public world","ttl":"1h","public":true}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("public create: got %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	rec = get(h, "/api/paste/"+created.ID)
	var meta struct {
		Data   string `json:"data"`
		Salt   string `json:"salt"`
		Public bool   `json:"public"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if rec.Code != 200 || meta.Data != "hello public world" || !meta.Public || meta.Salt != "" {
		t.Fatalf("public meta: got %d %+v", rec.Code, meta)
	}

	// the dashboard row carries the public marker (accounts-only surface)
	req := httptest.NewRequest("GET", "/api/shares", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), created.ID) || !strings.Contains(rec.Body.String(), `"public":true`) {
		t.Fatalf("share row missing public flag: %s", rec.Body)
	}

	// public + burn: read-then-delete still applies
	rec = postAs(t, h, "/api/paste", `{"data":"burn me","ttl":"1h","public":true,"burn":true}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("public burn create: got %d %s", rec.Code, rec.Body)
	}
	var burned struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &burned)
	if rec := get(h, "/api/paste/"+burned.ID); rec.Code != 200 {
		t.Fatalf("public burn first read: got %d", rec.Code)
	}
	if rec := get(h, "/api/paste/"+burned.ID); rec.Code != 404 {
		t.Fatalf("public burn second read: got %d, want 404", rec.Code)
	}
}

func TestPublicGuards(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	// abuse case: anonymous public create - the plaintext lane is accounts-only
	if rec := postAs(t, h, "/api/paste", `{"data":"x","ttl":"1h","public":true}`, ""); rec.Code != 403 {
		t.Fatalf("anon public create: got %d, want 403", rec.Code)
	}
	// passphrase + public is a contradiction
	if rec := postAs(t, h, "/api/paste", `{"data":"x","ttl":"1h","public":true,"salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, cookie); rec.Code != 400 {
		t.Fatalf("public with salt: got %d, want 400", rec.Code)
	}
	// empty text
	if rec := postAs(t, h, "/api/paste", `{"data":"","ttl":"1h","public":true}`, cookie); rec.Code != 400 {
		t.Fatalf("empty public text: got %d, want 400", rec.Code)
	}
	// oversize plaintext: same 64 KiB cap as ciphertext
	big := `{"data":"` + strings.Repeat("a", 64<<10+1) + `","ttl":"1h","public":true}`
	if rec := postAs(t, h, "/api/paste", big, cookie); rec.Code != 400 {
		t.Fatalf("oversize public text: got %d, want 400", rec.Code)
	}
	// data that would fail the base64url check is fine on the plaintext lane
	rec := postAs(t, h, "/api/paste", `{"data":"not base64url at all!","ttl":"1h","public":true}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("plaintext with spaces/punct: got %d %s", rec.Code, rec.Body)
	}
}

// custom slugs: public-only, validID-shaped (they become /p/ path segments),
// atomically claimed - a lost race is 409, never a silent overwrite
func TestPublicSlug(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	rec := postAs(t, h, "/api/paste", `{"data":"slugged paste","ttl":"1h","public":true,"slug":"my-notes-42"}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("slug create: got %d %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID != "my-notes-42" {
		t.Fatalf("slug ignored: %q", created.ID)
	}
	if rec := get(h, "/api/paste/my-notes-42"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "slugged paste") {
		t.Fatalf("slug meta read: got %d %s", rec.Code, rec.Body)
	}
	// the /p/ page itself serves (validID passes for the slug)
	if rec := get(h, "/p/my-notes-42"); rec.Code != 200 {
		t.Fatalf("slug page: got %d, want 200", rec.Code)
	}

	// duplicate slug -> 409, original untouched
	if rec := postAs(t, h, "/api/paste", `{"data":"hijack","ttl":"1h","public":true,"slug":"my-notes-42"}`, cookie); rec.Code != 409 {
		t.Fatalf("duplicate slug: got %d, want 409", rec.Code)
	}
	if rec := get(h, "/api/paste/my-notes-42"); !strings.Contains(rec.Body.String(), "slugged paste") {
		t.Fatalf("original paste clobbered: %s", rec.Body)
	}

	// bad shapes: too short, bad charset, too long
	for _, bad := range []string{"short", "has/slash", "way-way-way-too-long-slug"} {
		body := fmt.Sprintf(`{"data":"x","ttl":"1h","public":true,"slug":%q}`, bad)
		if rec := postAs(t, h, "/api/paste", body, cookie); rec.Code != 400 {
			t.Fatalf("bad slug %q: got %d, want 400", bad, rec.Code)
		}
	}
	// slugs are public-only
	if rec := postAs(t, h, "/api/paste", fmt.Sprintf(`{"data":%q,"ttl":"1h","slug":"enc-slug-1"}`, fakePayload()), cookie); rec.Code != 400 {
		t.Fatalf("slug on encrypted paste: got %d, want 400", rec.Code)
	}
}

// public bundles: plaintext envelope through the STANDARD chunked upload
// endpoints, accounts-only, optional custom slug claimed at finish
func TestPublicUpload(t *testing.T) {
	tinyChunks(t)
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	payload := []byte("hello public file content") // raw bytes, nothing encrypted
	rec := postAs(t, h, "/api/uploads", fmt.Sprintf(`{"len":%d,"ttl":"1h","public":true,"slug":"files-42"}`, len(payload)), cookie)
	if rec.Code != 200 {
		t.Fatalf("public init: got %d %s", rec.Code, rec.Body)
	}
	var init struct {
		ID        string `json:"id"`
		ChunkSize int64  `json:"chunkSize"`
		Chunks    int64  `json:"chunks"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &init)
	for n := int64(0); n < init.Chunks; n++ {
		off := n * init.ChunkSize
		end := min(off+init.ChunkSize, int64(len(payload)))
		if rec := put(t, h, fmt.Sprintf("/api/uploads/%s/%d", init.ID, n), payload[off:end], ""); rec.Code != 204 {
			t.Fatalf("chunk %d: got %d", n, rec.Code)
		}
	}
	rec = postAs(t, h, "/api/uploads/"+init.ID+"/finish", "", cookie)
	if rec.Code != 200 {
		t.Fatalf("public finish: got %d %s", rec.Code, rec.Body)
	}
	var fin struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &fin)
	if fin.ID != "files-42" {
		t.Fatalf("slug ignored: %q", fin.ID)
	}

	// meta: len, public, no salt, no data
	rec = get(h, "/api/paste/files-42")
	var meta struct {
		Len    int64  `json:"len"`
		Public bool   `json:"public"`
		Salt   string `json:"salt"`
		Data   string `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &meta)
	if rec.Code != 200 || meta.Len != int64(len(payload)) || !meta.Public || meta.Salt != "" || meta.Data != "" {
		t.Fatalf("public bundle meta: got %d %+v", rec.Code, meta)
	}
	// range reads return the raw plaintext bytes (paginated at CHUNK)
	var got []byte
	for off := int64(0); off < int64(len(payload)); {
		rec = get(h, "/api/paste/files-42/blob?offset="+fmt.Sprint(off))
		if rec.Code != 200 || rec.Body.Len() == 0 {
			t.Fatalf("public range read at %d: got %d %q", off, rec.Code, rec.Body.String())
		}
		got = append(got, rec.Body.Bytes()...)
		off += int64(rec.Body.Len())
	}
	if string(got) != string(payload) {
		t.Fatalf("public range reads lonely: got %q, want %q", got, payload)
	}
	// the /p/ page serves and double finish is idempotent under the slug
	if rec := get(h, "/p/files-42"); rec.Code != 200 {
		t.Fatalf("slug page: got %d, want 200", rec.Code)
	}
	if rec := postAs(t, h, "/api/uploads/"+init.ID+"/finish", "", cookie); rec.Code != 200 {
		t.Fatalf("double finish: got %d, want 200", rec.Code)
	}

	// abuse cases: anonymous, passphrase pairing, bad slug
	if rec := postAs(t, h, "/api/uploads", `{"len":10,"ttl":"1h","public":true}`, ""); rec.Code != 403 {
		t.Fatalf("anon public init: got %d, want 403", rec.Code)
	}
	if rec := postAs(t, h, "/api/uploads", `{"len":10,"ttl":"1h","public":true,"salt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, cookie); rec.Code != 400 {
		t.Fatalf("public init with salt: got %d, want 400", rec.Code)
	}
	if rec := postAs(t, h, "/api/uploads", `{"len":10,"ttl":"1h","public":true,"slug":"nope"}`, cookie); rec.Code != 400 {
		t.Fatalf("bad slug init: got %d, want 400", rec.Code)
	}
	if rec := postAs(t, h, "/api/uploads", `{"len":10,"ttl":"1h","slug":"enc-up-42"}`, cookie); rec.Code != 400 {
		t.Fatalf("slug on encrypted init: got %d, want 400", rec.Code)
	}

	// duplicate slug: a second session finishing under a taken name -> 409,
	// original paste untouched
	rec = postAs(t, h, "/api/uploads", `{"len":3,"ttl":"1h","public":true,"slug":"files-42"}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("dup init: got %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &init)
	if rec := put(t, h, fmt.Sprintf("/api/uploads/%s/0", init.ID), []byte{1, 2, 3}, ""); rec.Code != 204 {
		t.Fatalf("dup chunk: got %d", rec.Code)
	}
	if rec := postAs(t, h, "/api/uploads/"+init.ID+"/finish", "", cookie); rec.Code != 409 {
		t.Fatalf("dup finish: got %d, want 409", rec.Code)
	}
	if rec := get(h, "/api/paste/files-42"); !strings.Contains(rec.Body.String(), `"len":25`) || !strings.Contains(rec.Body.String(), `"public":true`) {
		t.Fatalf("original paste clobbered: %s", rec.Body)
	}
	// its blob is still readable and intact
	if rec := get(h, "/api/paste/files-42/blob?offset=0"); rec.Code != 200 || rec.Body.String() != string(payload[:8]) {
		t.Fatalf("original blob damaged: got %d %q", rec.Code, rec.Body.String())
	}
	// the aborted session dies cleanly
	req2 := httptest.NewRequest("DELETE", "/api/uploads/"+init.ID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req2)
	if rec.Code != 200 {
		t.Fatalf("abort dup session: got %d", rec.Code)
	}
}

func TestPublicDisabled(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)
	t.Setenv("PUBLIC_PASTES", "false")

	// signed-in or not: the plaintext lane is off, generic 400
	if rec := postAs(t, h, "/api/paste", `{"data":"x","ttl":"1h","public":true}`, cookie); rec.Code != 400 {
		t.Fatalf("disabled public create: got %d, want 400", rec.Code)
	}
	// capability probe carries the switch so the client hides the slider
	rec := get(h, "/api/gate")
	if !strings.Contains(rec.Body.String(), `"public":false`) {
		t.Fatalf("gate public flag: %s", rec.Body)
	}
	// the bundle lane is dead too
	if rec := postAs(t, h, "/api/uploads", `{"len":10,"ttl":"1h","public":true}`, cookie); rec.Code != 400 {
		t.Fatalf("disabled public upload init: got %d, want 400", rec.Code)
	}
}

func TestUploadRoundTrip(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "")
	// len 21 with chunks of 8: three chunks 8/8/5
	payload := make([]byte, 21)
	for i := range payload {
		payload[i] = byte(i)
	}
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h","burn":false}`)
	if rec.Code != 200 || ids.Chunks != 3 || ids.ChunkSze != 8 {
		t.Fatalf("init: got %d %s %+v", rec.Code, rec.Body, ids)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/0", payload[0:8], ""); rec.Code != 204 {
		t.Fatalf("chunk0: got %d %s", rec.Code, rec.Body)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/1", payload[8:16], ""); rec.Code != 204 {
		t.Fatalf("chunk1: got %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/2", payload[16:], ""); rec.Code != 204 {
		t.Fatalf("chunk2: got %d", rec.Code)
	}
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 200 {
		t.Fatalf("finish: got %d %s", rec.Code, rec.Body)
	}
	rec = get(h, "/api/paste/"+ids.ID)
	var meta struct {
		Len    int64  `json:"len"`
		Data   string `json:"data"`
		Burn   bool   `json:"burn"`
		Expiry int64  `json:"expires"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &meta) != nil {
		t.Fatalf("meta parse: %s", rec.Body)
	}
	if meta.Len != 21 || meta.Data != "" || meta.Burn || meta.Expiry == 0 {
		t.Fatalf("meta wrong: %+v", meta)
	}
	// reader paginates: range GETs at most chunkBytes each
	full := make([]byte, 0, 21)
	for off := int64(0); off < 21; off += 8 {
		rec = get(h, fmt.Sprintf("/api/paste/%s/blob?offset=%d", ids.ID, off))
		if rec.Code != 200 {
			t.Fatalf("blob range %d: got %d", off, rec.Code)
		}
		full = append(full, rec.Body.Bytes()...)
	}
	if !bytes.Equal(full, payload) {
		t.Fatalf("blob full: got %v want %v", full, payload)
	}
}

func TestUploadResumeOverwrite(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "")
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h"}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/0", []byte("11111111"), ""); rec.Code != 204 {
		t.Fatalf("first write: %d", rec.Code)
	}
	// resume: same index overwritten with the real chunk
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/0", []byte("22222222"), ""); rec.Code != 204 {
		t.Fatalf("resume write: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/1", []byte("33333333"), ""); rec.Code != 204 {
		t.Fatalf("chunk1: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/2", []byte("44444"), ""); rec.Code != 204 {
		t.Fatalf("chunk2: %d", rec.Code)
	}
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 200 {
		t.Fatalf("finish: %d %s", rec.Code, rec.Body)
	}
	// paginate like the reader does
	full := make([]byte, 0, 21)
	for off := int64(0); off < 21; off += 8 {
		if rec := get(h, fmt.Sprintf("/api/paste/%s/blob?offset=%d", ids.ID, off)); rec.Code != 200 {
			t.Fatalf("blob range %d: got %d", off, rec.Code)
		} else {
			full = append(full, rec.Body.Bytes()...)
		}
	}
	if string(full) != "222222223333333344444" {
		t.Fatalf("blob content: %q", string(full))
	}
}

func TestUploadFinishMissingPart(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "")
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h"}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), ""); rec.Code != 204 {
		t.Fatalf("chunk0: %d", rec.Code)
	}
	// parts 1 and 2 missing: finish fails but parts survive for retry
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 400 {
		t.Fatalf("partial finish: got %d, want 400", rec.Code)
	}
	// a stray oversized chunk must be rejected
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/1", make([]byte, 9), ""); rec.Code != 400 {
		t.Fatalf("oversize chunk: got %d, want 400", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/1", make([]byte, 8), ""); rec.Code != 204 {
		t.Fatalf("chunk1: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/2", make([]byte, 5), ""); rec.Code != 204 {
		t.Fatalf("chunk2: %d", rec.Code)
	}
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 200 {
		t.Fatalf("retry finish: %d %s", rec.Code, rec.Body)
	}
	if rec := get(h, "/api/paste/"+ids.ID); rec.Code != 200 {
		t.Fatalf("meta after retry finish: %d", rec.Code)
	}
	// double finish is idempotent
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 200 {
		t.Fatalf("double finish: %d", rec.Code)
	}
}

func TestUploadAbortCleans(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "")
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h"}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), "")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/uploads/"+ids.ID, nil))
	if rec.Code != 200 {
		t.Fatalf("abort: %d", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), ""); rec.Code != 404 {
		t.Fatalf("chunk after abort: got %d, want 404", rec.Code)
	}
	if rec := postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", ""); rec.Code != 404 {
		t.Fatalf("finish after abort: got %d, want 404", rec.Code)
	}
	// second abort is a benign no-op
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/api/uploads/"+ids.ID, nil))
	if rec.Code != 200 {
		t.Fatalf("second abort: %d", rec.Code)
	}
}

func TestUploadBadRequests(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "")
	for _, body := range []string{
		`{"len":0,"ttl":"1d"}`,                // empty
		`{"len":-1,"ttl":"1d"}`,               // negative
		`{"len":65,"ttl":"1d"}`,               // above cap
		`{"len":21,"ttl":"2w"}`,               // bad ttl
		`{"len":21}`,                          // empty ttl
		`{"len":21,"ttl":"1d","salt":"AA=="}`, // short salt
	} {
		rec := postTo(t, h, "/api/uploads", body, "")
		if rec.Code != 400 {
			t.Fatalf("init %q: got %d, want 400", body, rec.Code)
		}
	}
	// chunk path checks
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h"}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	for _, p := range []string{
		"/api/uploads/" + ids.ID + "/3",  // beyond chunk count
		"/api/uploads/" + ids.ID + "/-1", // negative
		"/api/uploads/" + ids.ID + "/xx", // junk
		"/api/uploads/abcdefgh:!/0",      // bad id charset (traversal gate)
	} {
		if rec := put(t, h, p, make([]byte, 8), ""); rec.Code == 204 {
			t.Fatalf("PUT %q: got 204, want 4xx", p)
		}
	}
}

func TestUploadSweep(t *testing.T) {
	tinyChunks(t)
	dir := t.TempDir()
	h := build(dir, "")
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1h"}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), "")
	// newborn session survives a normal sweep
	sweep(dir)
	if _, err := os.Stat(filepath.Join(dir, "uploads", ids.ID)); err != nil {
		t.Fatalf("fresh upload swept: %v", err)
	}
	// age the manifest past 2h: sweep removes the whole session
	mf := filepath.Join(dir, "uploads", ids.ID, "upload.json")
	if err := os.WriteFile(mf, []byte(`{"len":21,"ttl":"1h","created":`+fmt.Sprint(time.Now().Unix()-7200)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sweep(dir)
	if _, err := os.Stat(filepath.Join(dir, "uploads", ids.ID)); !os.IsNotExist(err) {
		t.Fatalf("stale upload survived: %v", err)
	}
}

func TestBlobBurnExpiresOnRead(t *testing.T) {
	tinyChunks(t)
	dir := t.TempDir()
	h := build(dir, "")
	ids, rec := initUpload(t, h, `{"len":21,"ttl":"1d","burn":true}`)
	if rec.Code != 200 {
		t.Fatalf("init: %d", rec.Code)
	}
	put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), "")
	put(t, h, "/api/uploads/"+ids.ID+"/1", make([]byte, 8), "")
	put(t, h, "/api/uploads/"+ids.ID+"/2", make([]byte, 5), "")
	postTo(t, h, "/api/uploads/"+ids.ID+"/finish", "", "")
	// first meta read must flip burn into the grace window, not nuke the blob mid-download
	if rec := get(h, "/api/paste/"+ids.ID); rec.Code != 200 {
		t.Fatalf("burn meta read: %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, ids.ID+".blob")); err != nil {
		t.Fatalf("blob vanished at meta read: %v", err)
	}
	if rec := get(h, "/api/paste/"+ids.ID+"/blob?offset=0"); rec.Code != 200 {
		t.Fatalf("blob in window: %d", rec.Code)
	}
	// expired meta + sweep reaps blob and meta
	reap := filepath.Join(dir, ids.ID+".json")
	if err := os.WriteFile(reap, []byte(`{"len":21,"burn":true,"expires":`+fmt.Sprint(time.Now().Unix()-1)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sweep(dir)
	if rec := get(h, "/api/paste/"+ids.ID+"/blob?offset=0"); rec.Code != 404 {
		t.Fatalf("blob after sweep: got %d, want 404", rec.Code)
	}
	// meta is gone too
	if rec := get(h, "/api/paste/"+ids.ID); rec.Code != 404 {
		t.Fatalf("meta after sweep: got %d, want 404", rec.Code)
	}
}

func TestAuthGateUpload(t *testing.T) {
	tinyChunks(t)
	h := build(t.TempDir(), "secret")
	rec := postTo(t, h, "/api/uploads", `{"len":21,"ttl":"1h"}`, "")
	if rec.Code != 401 {
		t.Fatalf("no key: got %d, want 401", rec.Code)
	}
	rec = postTo(t, h, "/api/uploads", `{"len":21,"ttl":"1h"}`, "wrong")
	if rec.Code != 401 {
		t.Fatalf("wrong key: got %d, want 401", rec.Code)
	}
	rec = postTo(t, h, "/api/uploads", `{"len":21,"ttl":"1h"}`, "secret")
	if rec.Code != 200 {
		t.Fatalf("good key: got %d %s, want 200", rec.Code, rec.Body)
	}
	var gated struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &gated) != nil || gated.ID == "" {
		t.Fatalf("no id with key: %s", rec.Body)
	}
	// chunks behind the gate too: no header -> 401, correct one -> 204
	if rec := put(t, h, "/api/uploads/"+gated.ID+"/0", make([]byte, 8), ""); rec.Code != 401 {
		t.Fatalf("ungated chunk: got %d, want 401", rec.Code)
	}
	if rec := put(t, h, "/api/uploads/"+gated.ID+"/0", make([]byte, 8), "secret"); rec.Code != 204 {
		t.Fatalf("gated chunk: got %d %s, want 204", rec.Code, rec.Body)
	}
}

// --- phase 2: identity sessions + active-shares dashboard ---
// (the webauthn ceremony itself needs a browser authenticator; these tests
// cover session-cookie auth, recording, and the dashboard listing.)

func testSession(t *testing.T, dir string) *sessions {
	t.Helper()
	s := newSessions(dir)
	ident := identity{
		ID:   newSessionID(),
		Name: "friend-of-tobias",
	}
	if err := s.saveIdentity(&ident); err != nil {
		t.Fatal(err)
	}
	return s
}

func sessionCookieFor(s *sessions) string {
	return "zp.session=" + s.sign(sessionClaims{
		Sub: func() string {
			// resolve the stored identity id
			// (only one identity was stored for this dir)
			entries, _ := os.ReadDir(filepath.Join(s.dir, "identities"))
			return strings.TrimSuffix(entries[0].Name(), ".json")
		}(),
		Exp: time.Now().Add(time.Hour).Unix(),
	})
}

func TestMeEndpoint(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")

	if rec := get(h, "/api/me"); rec.Code != 200 || strings.Contains(rec.Body.String(), `"name":"friend`) {
		t.Fatalf("anon me: got %d %s, want empty name", rec.Code, rec.Body)
	}
	if rec := get(h, "/api/me"); rec.Code == 200 {
		var me struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &me)
		if me.Name != "" {
			t.Fatalf("anon me leaked a name: %s", rec.Body)
		}
	}

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Cookie", sessionCookieFor(s))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "friend-of-tobias") {
		t.Fatalf("ident me: got %d %s", rec.Code, rec.Body)
	}
}

func TestFeatureSwitches(t *testing.T) {
	t.Run("accounts off", func(t *testing.T) {
		old := accountsOn
		accountsOn = false
		t.Cleanup(func() { accountsOn = old })
		h := build(t.TempDir(), "")

		rec := get(h, "/api/me")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"accounts":false`) {
			t.Fatalf("accounts flag: got %d %s", rec.Code, rec.Body)
		}
		// the ceremony routes disappear: dropped POSTs hit the GET / catch-all
		// and become 405 (method not allowed) - nothing identity-shaped answers
		if rec := postTo(t, h, "/api/identity/register/begin", `{"name":"x"}`, ""); rec.Code != 405 {
			t.Fatalf("register begin with accounts off: got %d, want 405", rec.Code)
		}
		if rec := postTo(t, h, "/api/identity/login/begin", "", ""); rec.Code != 405 {
			t.Fatalf("login begin with accounts off: got %d, want 405", rec.Code)
		}
		if rec := postTo(t, h, "/api/identity/logout", "", ""); rec.Code != 405 {
			t.Fatalf("logout with accounts off: got %d, want 405", rec.Code)
		}
	})

	t.Run("max ttl days", func(t *testing.T) {
		old := maxTTL
		maxTTL = 7
		t.Cleanup(func() { maxTTL = old })
		h := build(t.TempDir(), "")

		body := `{"data":"` + strings.Repeat("A", 40) + `","ttl":"8d"}`
		if rec := postTo(t, h, "/api/paste", body, ""); rec.Code != 400 {
			t.Fatalf("8d beyond 7d ceiling: got %d, want 400", rec.Code)
		}
		if rec := postTo(t, h, "/api/paste", `{"data":"`+strings.Repeat("A", 40)+`","ttl":"7d"}`, ""); rec.Code != 200 {
			t.Fatalf("7d within ceiling: got %d %s", rec.Code, rec.Body)
		}
		// /api/gate carries the ceiling for the client label
		rec := get(h, "/api/gate")
		if !strings.Contains(rec.Body.String(), `"maxTtlDays":7`) {
			t.Fatalf("gate payload: %s", rec.Body)
		}
	})

	t.Run("first user only", func(t *testing.T) {
		oldFirst, oldAlways := regFirstOnly, func() {}
		_ = oldAlways
		regFirstOnly = true
		t.Cleanup(func() { regFirstOnly = oldFirst })
		dir := t.TempDir()
		h := build(dir, "")

		// no identity yet: door open
		if rec := postTo(t, h, "/api/identity/register/begin", `{"name":"first"}`, ""); rec.Code != 200 {
			t.Fatalf("first-user bootstrap begin: got %d %s", rec.Code, rec.Body)
		}
		// one identity exists: door shut (seed directly, no ceremony needed)
		idents := filepath.Join(dir, "identities")
		if err := os.MkdirAll(idents, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(idents, "someone.json"), []byte(`{"id":"someone","name":"someone","creds":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec := postTo(t, h, "/api/identity/register/begin", `{"name":"late"}`, ""); rec.Code != 403 {
			t.Fatalf("registration after first user: got %d, want 403", rec.Code)
		}
		// /api/me reports registration closed
		if rec := get(h, "/api/me"); !strings.Contains(rec.Body.String(), `"open":false`) {
			t.Fatalf("me open flag: %s", rec.Body)
		}
	})

	t.Run("share cap", func(t *testing.T) {
		old := maxShares
		maxShares = 2
		t.Cleanup(func() { maxShares = old })
		dir := t.TempDir()
		s := testSession(t, dir)
		owns := newShareIndex(dir, s)
		h := build(dir, "")
		ident := t.TempDir() // reuse: make the ownership row live under the real ident id
		_ = ident

		// gadget: write the ownership rows the way record() would
		id := func(ident string, pasteID string, days int64) {
			t.Helper()
			if err := os.MkdirAll(filepath.Join(dir, "shares", ident), 0o700); err != nil {
				t.Fatal(err)
			}
			rows := filepath.Join(dir, "shares", ident, pasteID+".json")
			_ = os.WriteFile(rows, []byte(`{"created":0}`), 0o600)
			pb := filepath.Join(dir, pasteID+".json")
			_ = os.WriteFile(pb, []byte(fmt.Sprintf(`{"expires":%d}`, time.Now().Add(time.Duration(days)*24*time.Hour).Unix())), 0o600)
		}
		// what ident id does the test session carry?
		cookie := sessionCookieFor(s)
		req := httptest.NewRequest("GET", "/api/me", nil)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var me struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || me.ID == "" {
			t.Fatalf("session ident: %s %s", err, rec.Body)
		}
		id(me.ID, "act1", 1)
		if !owns.mayCreate(mustReq(cookie)) {
			t.Fatal("one active below cap: create should be allowed")
		}
		id(me.ID, "act2", 1)
		if owns.mayCreate(mustReq(cookie)) {
			t.Fatal("two actives at cap: create should be refused")
		}
		id(me.ID, "act2", -1) // same row now expired -> under cap again
		if !owns.mayCreate(mustReq(cookie)) {
			t.Fatal("expired rows do not count: create allowed again")
		}
	})
}

// mustReq: a request carrying the given cookie, for mayCreate assertions.
func mustReq(cookie string) *http.Request {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Cookie", cookie)
	return r
}

func TestReverseShares(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)
	pget := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	pdel := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("DELETE", path, nil)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	ppost := func(path, body, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		} else {
			req.Header.Set("Cookie", cookie)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// create: happy path + validation
	if rec := ppost("/api/rshare", `{"slug":"trip-photos","ttl":"7d","maxSize":104857600}`, ""); rec.Code != 200 {
		t.Fatalf("create inbox: got %d %s", rec.Code, rec.Body)
	}
	if rec := ppost("/api/rshare", `{"slug":"trip-photos","ttl":"7d","maxSize":1}`, ""); rec.Code != 409 {
		t.Fatalf("slug collision: got %d, want 409", rec.Code)
	}
	if rec := ppost("/api/rshare", `{"slug":"ab","ttl":"7d","maxSize":1}`, ""); rec.Code != 400 {
		t.Fatalf("short slug: got %d, want 400", rec.Code)
	}
	if rec := ppost("/api/rshare", `{"slug":"wrong!slug","ttl":"7d","maxSize":1}`, ""); rec.Code != 400 {
		t.Fatalf("bad slug charset: got %d, want 400", rec.Code)
	}
	if rec := ppost("/api/rshare", `{"slug":"week","ttl":"31d","maxSize":1}`, ""); rec.Code != 400 {
		t.Fatalf("ttl beyond ceiling: got %d, want 400", rec.Code)
	}
	if rec := ppost("/api/rshare", `{"slug":"huge","ttl":"1d","maxSize":68719476736}`, ""); rec.Code != 400 {
		t.Fatalf("maxSize beyond blob cap: got %d, want 400", rec.Code)
	}
	// list shows the owned inbox
	rec := pget("/api/rshares")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"slug":"trip-photos"`) || !strings.Contains(rec.Body.String(), `"uploads":0`) {
		t.Fatalf("list: got %d %s", rec.Code, rec.Body)
	}

	// a friend uploads a paste through the standard endpoint, then registers it
	reg := ppost("/api/paste", `{"data":"`+strings.Repeat("A", 40)+`","ttl":"7d"}`, "")
	if reg.Code != 200 {
		t.Fatalf("paste create: %d %s", reg.Code, reg.Body)
	}
	var pr struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(reg.Body.Bytes(), &pr)
	tripPaste := pr.ID
	if rec := ppost("/api/rshare/trip-photos/in", `{"id":"`+pr.ID+`"}`, "skip-cookie"); rec.Code != 200 {
		t.Fatalf("register upload: got %d %s", rec.Code, rec.Body)
	}
	if rec := ppost("/api/rshare/trip-photos/in", `{"id":"`+pr.ID+`"}`, "skip-cookie"); rec.Code != 200 {
		t.Fatalf("idempotent re-register: got %d %s", rec.Code, rec.Body)
	}
	rec = pget("/api/rshares")
	if !strings.Contains(rec.Body.String(), `"uploads":1`) {
		t.Fatalf("list upload count: %s", rec.Body)
	}
	// public meta hides inventory/owner
	rec = get(h, "/api/rshare/trip-photos")
	if !strings.Contains(rec.Body.String(), `"maxSize"`) || strings.Contains(rec.Body.String(), "owner") {
		t.Fatalf("public meta leak: %s", rec.Body)
	}
	// unknown upload ids rejected
	if rec := ppost("/api/rshare/trip-photos/in", `{"id":"AAAAAAAAAAAA"}`, "skip-cookie"); rec.Code != 404 {
		t.Fatalf("unknown upload: got %d, want 404", rec.Code)
	}
	// oversized upload rejected by inbox cap: MAX_UPLOAD override + fresh inbox
	oldCap := maxBlobBytes
	maxBlobBytes = 1 << 20
	t.Cleanup(func() { maxBlobBytes = oldCap })
	if rec := ppost("/api/rshare", `{"slug":"small","ttl":"1d","maxSize":65536}`, ""); rec.Code != 200 {
		t.Fatalf("small inbox create: %d %s", rec.Code, rec.Body)
	}
	reg = ppost("/api/paste", `{"data":"`+strings.Repeat("A", 40)+`","ttl":"1h"}`, "")
	if reg.Code != 200 {
		t.Fatalf("paste create small: %d", reg.Code)
	}
	_ = json.Unmarshal(reg.Body.Bytes(), &pr)
	// the bundle cap counts blob Len: fake a bundle-sized paste on disk
	if err := os.WriteFile(filepath.Join(dir, pr.ID+".json"), []byte(`{"expires":4102444800,"len":1048576}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := ppost("/api/rshare/small/in", `{"id":"`+pr.ID+`"}`, "skip-cookie"); rec.Code != 403 {
		t.Fatalf("oversized upload: got %d, want 403", rec.Code)
	}

	// delete with contents wipes the inbox and the registered paste
	if rec := pdel("/api/rshare/trip-photos"); rec.Code != 200 {
		t.Fatalf("delete inbox: got %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(dir, "inboxes", "trip-photos.json")); !os.IsNotExist(err) {
		t.Fatalf("inbox file survived delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, tripPaste+".json")); !os.IsNotExist(err) {
		t.Fatalf("registered paste survived inbox delete: %v", err)
	}
	if rec := pget("/api/rshares"); strings.Contains(rec.Body.String(), "trip-photos") {
		t.Fatalf("deleted inbox still listed: %s", rec.Body)
	}
	// own second inbox deletes; a missing one 404s
	if rec := pdel("/api/rshare/small"); rec.Code != 200 {
		t.Fatalf("delete own second inbox: %d %s", rec.Code, rec.Body)
	}
	if rec := pdel("/api/rshare/small"); rec.Code != 404 {
		t.Fatalf("double delete: got %d, want 404", rec.Code)
	}
	rec = postTo(t, h, "/api/rshare", `{"slug":"anontry","ttl":"1d","maxSize":1}`, "")
	if rec.Code != 401 {
		t.Fatalf("anon create: got %d, want 401", rec.Code)
	}
}

func TestSharesRecordAndList(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)
	// signed-in create records a row
	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(fmt.Sprintf(`{"data":%q,"ttl":"1h"}`, fakePayload())))
	req.Header.Add("Cookie", cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("create: %d", rec.Code)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// record kind text: row appears, kind from meta; no data leak
	req = httptest.NewRequest("GET", "/api/shares", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var rows []struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		Data    string `json:"data,omitempty"`
		Expires int64  `json:"expires"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &rows) != nil {
		t.Fatalf("shares parse: %s", rec.Body)
	}
	if len(rows) != 1 || rows[0].ID != created.ID || rows[0].Kind != "text" || rows[0].Data != "" {
		t.Fatalf("rows: %+v", rows)
	}

	// anon create records nothing
	rec = post(t, h, fmt.Sprintf(`{"data":%q,"ttl":"1h"}`, fakePayload()))
	if rec.Code != 200 {
		t.Fatalf("anon create: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/shares", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &rows)
	if len(rows) != 1 {
		t.Fatalf("anon create leaked into shares: %d rows", len(rows))
	}

	// expired shares self-prune from the listing
	if err := os.WriteFile(filepath.Join(dir, created.ID+".json"),
		[]byte(`{"data":"x","expires":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/api/shares", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &rows)
	if len(rows) != 0 {
		t.Fatalf("expired row survived: %+v", rows)
	}
	if _, err := os.Stat(filepath.Join(dir, "shares", func() string {
		entries, _ := os.ReadDir(filepath.Join(dir, "identities"))
		return strings.TrimSuffix(entries[0].Name(), ".json")
	}(), created.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("ownership row was not pruned with the paste")
	}
}

func TestRegistrationClosed(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	t.Setenv("REG_OPEN", "false")
	h := build(dir, "")

	// anonymous register -> 403
	rec := postTo(t, h, "/api/identity/register/begin", `{"name":"x"}`, "")
	if rec.Code != 403 {
		t.Fatalf("closed register: got %d, want 403", rec.Code)
	}
	// login stays open (nothing registered -> 404 from begin... served as 404-shaped error)
	rec = postTo(t, h, "/api/identity/login/begin", "", "")
	if rec.Code != 200 && rec.Code != 404 {
		t.Fatalf("login begin when closed: got %d, want 200 (allowlist may be empty)", rec.Code)
	}
	// signed-in attach allowed even when closed
	cookie := sessionCookieFor(s)
	req := httptest.NewRequest("POST", "/api/identity/register/begin", strings.NewReader(`{}`))
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("attach register when closed: got %d %s, want options", rec.Code, rec.Body)
	}
	// me advertises openness
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["open"] != false {
		t.Fatalf("open flag: %+v", me)
	}
}

// skill gate: session cookie carries Secure on HTTPS origins, stays usable
// on deliberate plain-HTTP LAN deployments (SameSite/HttpOnly asserted too).
func TestSessionCookieFlags(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	call := func(headers map[string]string) map[string]*http.Cookie {
		req := httptest.NewRequest("POST", "/api/identity/logout", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		out := map[string]*http.Cookie{}
		for _, c := range rec.Result().Cookies() {
			out[c.Name] = c
		}
		return out
	}

	// logout over plain http: clears cookie without Secure, flags intact
	got := call(nil)
	if c := got[sessionCookie]; c == nil {
		t.Fatal("no clearing cookie returned")
	} else if c.Secure {
		t.Fatal("Secure set on plain http origin")
	} else if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags: %+v", c)
	}

	// proxied https: Secure present
	got = call(map[string]string{"X-Forwarded-Proto": "https"})
	if c := got[sessionCookie]; c == nil {
		t.Fatal("no cookie for https origin")
	} else if !c.Secure {
		t.Fatal("Secure missing on X-Forwarded-Proto https")
	}
}

// The finish endpoints must read the request body exactly once: sessionId
// extraction and the ceremony parser used to race over r.Body, so the second
// reader hit EOF ('registration failed' / 'invalid login response').
func TestCeremonyBodySingleRead(t *testing.T) {
	dir := t.TempDir()
	h := build(dir, "")

	// begin caches the ceremony in memory
	begun, rec := func() (string, *httptest.ResponseRecorder) {
		rec := postTo(t, h, "/api/identity/register/begin", `{"name":"t"}`, "")
		if rec.Code != 200 {
			t.Fatalf("begin: %d %s", rec.Code, rec.Body)
		}
		var out struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.SessionID == "" {
			t.Fatalf("begin: no session id: %s", rec.Body)
		}
		return out.SessionID, rec
	}()

	// finish without a sessionId -> invalid request body, not unknown session
	rec = postTo(t, h, "/api/identity/register/finish", `{"response":{}}`, "")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid request body") {
		t.Fatalf("no sessionId: %d %s", rec.Code, rec.Body)
	}
	// finish with a junk (not-begun) session id -> unknown session
	rec = postTo(t, h, "/api/identity/register/finish", `{"sessionId":"nope"}`, "")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "unknown session") {
		t.Fatalf("junk sessionId: %d %s", rec.Code, rec.Body)
	}
	// finish with the begun id + a non-credential payload -> parser error,
	// which proves the body reached the ceremony parser in full
	rec = postTo(t, h, "/api/identity/register/finish", `{"sessionId":"`+begun+`"}`, "")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "registration failed") {
		t.Fatalf("junk credential: %d %s", rec.Code, rec.Body)
	}
	// login finish behaves the same
	rec = postTo(t, h, "/api/identity/login/finish", `{"response":{}}`, "")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid request body") {
		t.Fatalf("login no sessionId: %d %s", rec.Code, rec.Body)
	}
	rec = postTo(t, h, "/api/identity/login/finish", `{"sessionId":"nope"}`, "")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "unknown session") {
		t.Fatalf("login junk sessionId: %d %s", rec.Code, rec.Body)
	}
}

// aggregated opens counter: two meta reads = views 2, and the counter must
// survive burn-flip rewrites but NOT text-burn deletion
func TestViewsCounter(t *testing.T) {
	dir := t.TempDir()
	h := build(dir, "")
	rec := post(t, h, fmt.Sprintf(`{"data":%q,"ttl":"1h","burn":true}`, fakePayload()))
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	_ = get(h, "/api/paste/"+created.ID)
	var meta struct {
		Views int `json:"views"`
	}
	_ = json.Unmarshal(get(h, "/api/paste/"+created.ID).Body.Bytes(), &meta)
	if meta.Views > 2 {
		t.Fatalf("burned text counted on deletion path: %d", meta.Views)
	}

	// non-burned bundle: meta read increments persist per open
	tinyChunks(t)
	s := testSession(t, dir)
	cookie := sessionCookieFor(s)
	// signed-in upload so the dash row records with a session cookie
	upReq := httptest.NewRequest("POST", "/api/uploads", strings.NewReader(`{"len":21,"ttl":"1h"}`))
	upReq.Header.Add("Cookie", cookie)
	urec := httptest.NewRecorder()
	h.ServeHTTP(urec, upReq)
	if urec.Code != 200 {
		t.Fatalf("signed init: %d", urec.Code)
	}
	ids := struct {
		ID       string `json:"id"`
		Chunks   int64  `json:"chunks"`
		ChunkSze int64  `json:"chunkSize"`
	}{}
	if json.Unmarshal(urec.Body.Bytes(), &ids) != nil {
		t.Fatalf("signed init body: %s", urec.Body)
	}
	put(t, h, "/api/uploads/"+ids.ID+"/0", make([]byte, 8), "")
	put(t, h, "/api/uploads/"+ids.ID+"/1", make([]byte, 8), "")
	put(t, h, "/api/uploads/"+ids.ID+"/2", make([]byte, 5), "")
	// finish under the same cookie so the share row lands
	req := httptest.NewRequest("POST", "/api/uploads/"+ids.ID+"/finish", nil)
	req.Header.Add("Cookie", cookie)
	frec := httptest.NewRecorder()
	h.ServeHTTP(frec, req)
	if frec.Code != 200 {
		t.Fatalf("signed finish: %d", frec.Code)
	}
	var views int64
	for i := 0; i < 3; i++ {
		get(h, "/api/paste/"+ids.ID)
		_ = json.Unmarshal(get(h, "/api/paste/"+ids.ID).Body.Bytes(), &meta)
		if meta.Views < int(views) {
			t.Fatalf("views went backwards: %d -> %d", views, meta.Views)
		}
		views = int64(meta.Views)
	}
	if views < 5 {
		t.Fatalf("expected >=5 opens (1 upload + 6 meta reads), got %d", views)
	}
	// shares listing carries the counter (with the session cookie)
	dreq := httptest.NewRequest("GET", "/api/shares", nil)
	dreq.Header.Add("Cookie", cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, dreq)
	var rows []map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &rows)
	if len(rows) == 0 || rows[0]["views"] == nil {
		t.Fatalf("shares rows missing views: %v", rows)
	}
}

// display-name edit: signed-in persistence, anon rejected
func TestNameEdit(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	rec := postTo(t, h, "/api/identity/name", `{"name":"tobby"}`, "")
	if rec.Code != 401 {
		t.Fatalf("anon name edit: got %d, want 401", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/identity/name", strings.NewReader(`{"name":"tobias "}`))
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "tobias") {
		t.Fatalf("name edit: %d %s", rec.Code, rec.Body)
	}
	// me reflects the new name (session claims unchanged; identity file updated)
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Add("Cookie", cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "tobias") {
		t.Fatalf("me after rename: %s", rec.Body)
	}
	// blank/oversized names rejected
	for _, n := range []string{`{"name":""}`, `{"name":"` + strings.Repeat("x", 65) + `"}`} {
		req = httptest.NewRequest("POST", "/api/identity/name", strings.NewReader(n))
		req.Header.Add("Cookie", cookie)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("bad name %q: got %d, want 400", n, rec.Code)
		}
	}
}

// ---- admin config tab: session-gated view/patch/apply over data/config.json ----

func adminDo(h http.Handler, method, path, body, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type cfgKnob struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Set    bool   `json:"set"`
	Value  any    `json:"value"`
}
type adminView struct {
	Knobs         []cfgKnob `json:"knobs"`
	RestartNeeded bool      `json:"restartNeeded"`
}

func knobOf(t *testing.T, body []byte, name string) cfgKnob {
	t.Helper()
	var v adminView
	if json.Unmarshal(body, &v) != nil {
		t.Fatalf("unparseable admin view: %s", body)
	}
	for _, k := range v.Knobs {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("knob %q missing from view: %s", name, body)
	return cfgKnob{}
}

func TestAdminConfigGate(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	// abuse case: anonymous visitors must draw blank on all three verbs
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/admin/config", ""},
		{"PUT", "/api/admin/config", `{"maxTtlDays":10}`},
		{"POST", "/api/admin/apply", ""},
	} {
		if rec := adminDo(h, c.method, c.path, c.body, ""); rec.Code != 403 {
			t.Fatalf("anon %s %s: got %d, want 403", c.method, c.path, rec.Code)
		}
	}

	if rec := adminDo(h, "GET", "/api/admin/config", "", cookie); rec.Code != 200 {
		t.Fatalf("signed GET: got %d %s", rec.Code, rec.Body)
	} else {
		var v adminView
		if json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("unparseable view: %s", rec.Body)
		}
		if len(v.Knobs) != 8 {
			t.Fatalf("want the full knob set, got %d: %s", len(v.Knobs), rec.Body)
		}
		if k := knobOf(t, rec.Body.Bytes(), "CREATE_KEY"); k.Kind != "secret" || k.Set || k.Value != nil {
			t.Fatalf("CREATE_KEY must be an unset secret, got %+v", k)
		}
		if k := knobOf(t, rec.Body.Bytes(), "PASTE_ACCESS"); k.Kind != "choice" || k.Value != "open" || k.Source != "default" {
			t.Fatalf("PASTE_ACCESS default echo wrong: %+v", k)
		}
		if k := knobOf(t, rec.Body.Bytes(), "REGISTRATION"); k.Kind != "choice" || k.Value != "open" {
			t.Fatalf("REGISTRATION default echo wrong: %+v", k)
		}
		if k := knobOf(t, rec.Body.Bytes(), "MAX_TTL_DAYS"); k.Value != float64(30) || k.Source != "default" {
			t.Fatalf("MAX_TTL_DAYS default echo wrong: %+v", k)
		}
		if v.RestartNeeded {
			t.Fatal("fresh boot must not claim a pending restart")
		}
	}
}

func TestAdminConfigPrecedence(t *testing.T) {
	// env layer (compose): reg closed through env
	t.Setenv("REG_OPEN", "false")
	dir := t.TempDir()

	// file layer overrides env for the knob it names and leaves the rest
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"registration":"open","maxTtlDays":20}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"maxTtlDays":20`) {
		t.Fatalf("file must beat env for the ceiling: %s", rec.Body)
	}
	s := testSession(t, dir) // identity belongs to the SAME dir; loaded AFTER build above
	cookie := sessionCookieFor(s)
	rec := adminDo(h, "GET", "/api/admin/config", "", cookie)
	if k := knobOf(t, rec.Body.Bytes(), "REGISTRATION"); k.Source != "file" || k.Value != "open" {
		t.Fatalf("registration file layer lost: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "PUBLIC_PASTES"); k.Source != "default" || k.Value != true {
		t.Fatalf("unnamed knob must fall through to env/default: %+v", k)
	}
	// first-user bootstrap UNCHANGED by the file (env default: no close)
	var me struct {
		Open bool `json:"open"`
	}
	json.Unmarshal(adminDo(h, "GET", "/api/me", "", cookie).Body.Bytes(), &me)
	if !me.Open {
		t.Fatal("registration file layer says open - /api/me open must stay true")
	}

	// invite close via file: registration=invite closes fresh sign-up
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"registration":"invite"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	json.Unmarshal(adminDo(h, "GET", "/api/me", "", cookie).Body.Bytes(), &me)
	if me.Open {
		t.Fatal("registration file invite must close fresh registration for /api/me")
	}

	// env-only fallback: no file -> the boot layer resurfaces (REG_OPEN env
	// read lives at the guard; int ceiling returns to the init()-default 30)
	if err := os.Remove(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"maxTtlDays":30`) {
		t.Fatalf("boot ceiling must resurface without the file: %s", rec.Body)
	}
	json.Unmarshal(adminDo(h, "GET", "/api/me", "", cookie).Body.Bytes(), &me)
	if me.Open {
		t.Fatal("env REG_OPEN=false must resurface without the file")
	}
}

func TestAdminConfigValidation(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)
	bad := []string{
		`{"maxTtlDays":0}`,             // below floor
		`{"maxTtlDays":400}`,           // above ceiling
		`{"maxShares":-1}`,             // negative
		`{"maxUpload":100}`,            // below 1 MiB
		`{"chunk":1024}`,               // below 64 KiB
		`{"chunk":67108865}`,           // above 64 MiB
		`{"chunk":68719476736}`,        // chunk above maxUpload headroom
		`{"regOpen":"yes"}`,            // wrong type
		`{"accountsOff":true}`,         // unknown field: USER_ACCOUNTS is env-only on purpose
		`{"pasteAccess":"chaos"}`,      // invalid mode
		`{"registration":"chaos"}`,     // invalid mode
		`{"pasteAccess":"passphrase"}`, // passphrase with no key anywhere
		`not-json`,                     // undecodable
	}
	for _, b := range bad {
		if rec := adminDo(h, "PUT", "/api/admin/config", b, cookie); rec.Code != 400 {
			t.Fatalf("bad patch %s: got %d, want 400", b, rec.Code)
		}
	}
	// the file must be untouched by the whole failed batch
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Fatal("failed puts must not have written a config file")
	}
}

func TestAdminConfigPersistence(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	rec := adminDo(h, "PUT", "/api/admin/config", `{"maxTtlDays":200,"createKey":"gate-pass","pasteAccess":"passphrase","registration":"invite"}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("PUT: got %d %s", rec.Code, rec.Body)
	}
	if k := knobOf(t, rec.Body.Bytes(), "MAX_TTL_DAYS"); k.Source != "file" || k.Value != float64(200) {
		t.Fatalf("view after PUT: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "PASTE_ACCESS"); k.Source != "file" || k.Value != "passphrase" {
		t.Fatalf("PASTE_ACCESS view after PUT: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "REGISTRATION"); k.Source != "file" || k.Value != "invite" {
		t.Fatalf("REGISTRATION view after PUT: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "CREATE_KEY"); !k.Set || k.Value != nil {
		t.Fatalf("CREATE_KEY masked in view: %+v", k)
	}
	if !strings.Contains(rec.Body.String(), `"restartNeeded":true`) {
		t.Fatalf("PUT after boot must flag restart: %s", rec.Body)
	}
	// frozen contract: the RUNNING process must not adopt the file values -
	// a mid-boot ceiling change would strand in-flight chunked uploads
	if rec := get(h, "/api/gate"); strings.Contains(rec.Body.String(), `"maxTtlDays":200`) {
		t.Fatalf("running knobs must stay frozen until the apply-restart: %s", rec.Body)
	}
	// storage: 0600, masked secret readable, but never echoed
	fi, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode: %v %v", err, fi)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if !strings.Contains(string(raw), `"createKey":"gate-pass"`) {
		t.Fatalf("gate key not persisted: %s", raw)
	}

	// the boot applies the file: a pristine process shows the saved state live
	h2 := build(dir, "")
	rec2 := adminDo(h2, "GET", "/api/admin/config", "", cookie)
	if k := knobOf(t, rec2.Body.Bytes(), "MAX_TTL_DAYS"); k.Source != "file" || k.Value != float64(200) {
		t.Fatalf("fresh boot lost the file layer: %+v", k)
	}
	if strings.Contains(rec2.Body.String(), `"restartNeeded":true`) {
		t.Fatal("a boot that loaded the file must not claim a pending restart", rec2.Body)
	}
	if rec := get(h2, "/api/gate"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"maxTtlDays":200`) {
		t.Fatalf("gate echo after boot: got %d %s", rec.Code, rec.Body)
	}

	// the create-gate must follow the file key: anon 401, bearer 200
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())
	if rec := adminDo(h2, "POST", "/api/paste", body, ""); rec.Code != 401 {
		t.Fatalf("create without gate key: got %d, want 401", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer gate-pass")
	recOk := httptest.NewRecorder()
	h2.ServeHTTP(recOk, req)
	if recOk.Code != 200 {
		t.Fatalf("create with file gate key: got %d %s", recOk.Code, recOk.Body)
	}
}

func TestAdminConfigRestartFlow(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	calls := 0
	restartServer = func() { calls++ }
	defer func() { restartServer = nil }()

	if rec := adminDo(h, "POST", "/api/admin/apply", "", cookie); rec.Code != 200 {
		t.Fatalf("apply: got %d %s", rec.Code, rec.Body)
	}
	// second apply while the first drain is pending must 409
	if rec := adminDo(h, "POST", "/api/admin/apply", "", cookie); rec.Code != 409 {
		t.Fatalf("double apply: got %d, want 409", rec.Code)
	}
	if calls != 0 {
		t.Fatal("restart hook fired before its 300ms grace window")
	}
	time.Sleep(600 * time.Millisecond)
	if calls != 1 {
		t.Fatalf("restart hook fired %d times, want exactly 1", calls)
	}
}

// ---- v0.12.1: exclusive paste-access + registration modes ----

// old config files migrate: the legacy locked/createKey and
// regOpen/userRegistration encodings resolve to the exclusive modes without
// an admin visit, and a new-shape PUT clears the legacy fields it supersedes
func TestAdminConfigMigration(t *testing.T) {
	dir := t.TempDir()
	// legacy: locked=true wins the stricter slot; the key stays set in the file
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"locked":true,"createKey":"old-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":true`) || strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("legacy locked file must migrate to members mode, gate off: %s", rec.Body)
	}
	s := testSession(t, dir)
	cookie := sessionCookieFor(s)
	rec := adminDo(h, "GET", "/api/admin/config", "", cookie)
	if k := knobOf(t, rec.Body.Bytes(), "PASTE_ACCESS"); k.Value != "members" || k.Source != "file" {
		t.Fatalf("legacy locked must echo as members/file: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "CREATE_KEY"); !k.Set {
		t.Fatalf("legacy key must stay masked-set: %+v", k)
	}

	// legacy: regOpen=false migrates to invite; a new-shape PUT replaces it
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"regOpen":false,"locked":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	rec = adminDo(h, "GET", "/api/admin/config", "", cookie)
	if k := knobOf(t, rec.Body.Bytes(), "REGISTRATION"); k.Value != "invite" || k.Source != "file" {
		t.Fatalf("legacy regOpen=false must echo as invite/file: %+v", k)
	}
	if k := knobOf(t, rec.Body.Bytes(), "PASTE_ACCESS"); k.Value != "open" {
		t.Fatalf("legacy locked=false must echo as open: %+v", k)
	}
	if rec := adminDo(h, "PUT", "/api/admin/config", `{"pasteAccess":"open","registration":"open"}`, cookie); rec.Code != 200 {
		t.Fatalf("PUT over legacy file: got %d %s", rec.Code, rec.Body)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if strings.Contains(string(raw), `"regOpen"`) || strings.Contains(string(raw), `"locked"`) {
		t.Fatalf("new-shape PUT must clear the legacy fields it supersedes: %s", raw)
	}
	if k := knobOf(t, adminDo(h, "GET", "/api/admin/config", "", cookie).Body.Bytes(), "REGISTRATION"); k.Value != "open" || k.Source != "file" {
		t.Fatal("new registration field did not persist")
	}
}

// the three paste-access modes are exclusive: open ignores a stale key,
// passphrase gates by bearer, members by session
func TestPasteAccessModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"pasteAccess":"passphrase","createKey":"mode-pass"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"enabled":true`) || strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("passphrase mode probe: %s", rec.Body)
	}
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())
	if rec := adminDo(h, "POST", "/api/paste", body, ""); rec.Code != 401 {
		t.Fatalf("passphrase mode anon create: got %d, want 401", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/paste", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer mode-pass")
	recOk := httptest.NewRecorder()
	h.ServeHTTP(recOk, req)
	if recOk.Code != 200 {
		t.Fatalf("passphrase mode bearer create: got %d %s", recOk.Code, recOk.Body)
	}

	// members mode: the session is the only gate; a stale key must not demand a bearer
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"pasteAccess":"members","createKey":"stale-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	if rec := get(h, "/api/gate"); strings.Contains(rec.Body.String(), `"enabled":true`) || !strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("members mode probe: %s", rec.Body)
	}
	if rec := adminDo(h, "POST", "/api/paste", body, ""); rec.Code != 403 {
		t.Fatalf("members mode anon create: got %d, want 403", rec.Code)
	}
	s := testSession(t, dir)
	if rec := adminDo(h, "POST", "/api/paste", body, sessionCookieFor(s)); rec.Code != 200 {
		t.Fatalf("members mode signed create: got %d %s", rec.Code, rec.Body)
	}

	// open mode with a stale key in the file: no gate at all
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"pasteAccess":"open","createKey":"stale-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	if rec := get(h, "/api/gate"); strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("open mode must not enable the gate: %s", rec.Body)
	}
	if rec := adminDo(h, "POST", "/api/paste", body, ""); rec.Code != 200 {
		t.Fatalf("open mode anon create: got %d %s", rec.Code, rec.Body)
	}
}

// the janitor must not eat the admin config: a bare {"maxTtlDays":14} parses
// as an all-zero paste (expires 0 < now) and would otherwise vanish on the
// very first sweep
func TestSweepKeepsConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"maxTtlDays":14}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sweep(dir)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Fatal("sweep deleted data/config.json")
	}
}

// ---- v0.11: locked compose lane + invite links ----

func TestLockedCompose(t *testing.T) {
	t.Setenv("LOCKED", "true")
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())

	// the gate probe carries the posture so the client can render the lock card
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("gate probe locked flag: %s", rec.Body)
	}

	// abuse case: anonymous visitors must not create anything
	if rec := adminDo(h, "POST", "/api/paste", body, ""); rec.Code != 403 {
		t.Fatalf("anon create locked: got %d, want 403", rec.Code)
	}
	if rec := adminDo(h, "POST", "/api/uploads", `{"len":100,"ttl":"1d"}`, ""); rec.Code != 403 {
		t.Fatalf("anon upload init locked: got %d, want 403", rec.Code)
	}
	if rec := adminDo(h, "POST", "/api/uploads/abcdefghijk/finish", "", ""); rec.Code != 403 {
		t.Fatalf("anon upload finish locked: got %d, want 403", rec.Code)
	}

	// reads stay open for anonymous visitors - the zero-knowledge contract
	// never depends on an account
	if rec := get(h, "/api/gate"); rec.Code != 200 {
		t.Fatalf("gate probe: got %d", rec.Code)
	}

	// signed-in identities create freely
	if rec := adminDo(h, "POST", "/api/paste", body, cookie); rec.Code != 200 {
		t.Fatalf("signed create locked: got %d %s", rec.Code, rec.Body)
	}
}

func TestLockedConfigKnob(t *testing.T) {
	// file layer beats env for the lock switch
	t.Setenv("LOCKED", "true")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"locked":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":false`) {
		t.Fatalf("file lock=false must beat env=true: %s", rec.Body)
	}
	if err := os.Remove(filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	h = build(dir, "")
	if rec := get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("env lock resurfaces without the file: %s", rec.Body)
	}
}

func TestInviteLifecycle(t *testing.T) {
	// a closed instance is the invite mode's home turf
	t.Setenv("REG_OPEN", "false")
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	// anonymous admin surface is closed
	if rec := adminDo(h, "POST", "/api/admin/invites", `{}`, ""); rec.Code != 403 {
		t.Fatalf("anon invite create: got %d, want 403", rec.Code)
	}
	if rec := adminDo(h, "GET", "/api/admin/invites", "", ""); rec.Code != 403 {
		t.Fatalf("anon invite list: got %d, want 403", rec.Code)
	}

	// mint: default single use
	rec := adminDo(h, "POST", "/api/admin/invites", `{"uses":2}`, cookie)
	if rec.Code != 200 {
		t.Fatalf("invite create: got %d %s", rec.Code, rec.Body)
	}
	var minted struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &minted) != nil || len(minted.Token) != 22 {
		t.Fatalf("invite token shape: %s", rec.Body)
	}

	// list shows it
	rec = adminDo(h, "GET", "/api/admin/invites", "", cookie)
	if !strings.Contains(rec.Body.String(), `"uses":0`) || !strings.Contains(rec.Body.String(), `"maxUses":2`) {
		t.Fatalf("invite list missing row: %s", rec.Body)
	}

	// unit-level gate: closed registration rejects no-token anon, accepts the live token
	if ok, why := s.inviteGate(""); ok {
		t.Fatal("closed instance must reject an absent token")
	} else if !strings.Contains(why, "closed") {
		t.Fatalf("why: %q", why)
	}
	if ok, _ := s.inviteGate(minted.Token); !ok {
		t.Fatal("live invite must pass the gate")
	}
	if ok, _ := s.inviteGate("!!bad-token-shape!!"); ok {
		t.Fatal("malformed token must fail")
	}
	if ok, _ := s.inviteGate(strings.Repeat("A", 22)); ok {
		t.Fatal("unknown token must fail")
	}

	// consume: two uses allowed, third rejected, file gone at exhaustion
	s.inviteConsume(minted.Token)
	if ok, _ := s.inviteGate(minted.Token); !ok {
		t.Fatal("second use still valid")
	}
	s.inviteConsume(minted.Token)
	if ok, _ := s.inviteGate(minted.Token); ok {
		t.Fatal("exhausted invite must fail the gate")
	}
	if _, err := os.Stat(filepath.Join(invitesDir(dir), minted.Token+".json")); !os.IsNotExist(err) {
		t.Fatal("exhausted invite file not removed")
	}

	// revoke: delete endpoint removes the invite file
	rec = adminDo(h, "POST", "/api/admin/invites", `{}`, cookie)
	json.Unmarshal(rec.Body.Bytes(), &minted)
	if rec := adminDo(h, "DELETE", "/api/admin/invites/"+minted.Token, "", cookie); rec.Code != 200 {
		t.Fatalf("revoke: got %d", rec.Code)
	}
	if ok, _ := s.inviteGate(minted.Token); ok {
		t.Fatal("revoked invite must fail")
	}
	// idempotent second revoke
	if rec := adminDo(h, "DELETE", "/api/admin/invites/"+minted.Token, "", cookie); rec.Code != 200 {
		t.Fatalf("second revoke: got %d", rec.Code)
	}
	// bad token charset on the delete path
	if rec := adminDo(h, "DELETE", "/api/admin/invites/bad!!", "", cookie); rec.Code != 404 {
		t.Fatalf("bad revoke token: got %d, want 404", rec.Code)
	}
}

func TestInviteRegisterFlow(t *testing.T) {
	// closed instance: begin carries the invite; finish re-validates and
	// consumes only on success. The webauthn ceremony itself cannot run on an
	// IP-literal httptest host (begin 400s) - the invite gate logic around it
	// is what these assertions cover.
	t.Setenv("REG_OPEN", "false")
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")

	rec := adminDo(h, "POST", "/api/admin/invites", `{}`, sessionCookieFor(s))
	var minted struct {
		Token string `json:"token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &minted)

	// anon begin WITHOUT token -> 403 closed (pre-existing posture)
	if rec := adminDo(h, "POST", "/api/identity/register/begin", `{"name":"x"}`, ""); rec.Code != 403 {
		t.Fatalf("anon begin closed: got %d, want 403", rec.Code)
	}
	// anon begin with a MALFORMED token -> 403 with the malformed message
	if rec := adminDo(h, "POST", "/api/identity/register/begin", `{"name":"x","invite":"bad!!"}`, ""); rec.Code != 403 || !strings.Contains(rec.Body.String(), "malformed") {
		t.Fatalf("anon begin malformed invite: got %d %s", rec.Code, rec.Body)
	}
	// anon begin with a LIVE token passes the invite gate and reaches the
	// ceremony (httptest.NewRequest carries Host example.com - a domain, so
	// webauthn builds fine and the begin answers with real options)
	rec = adminDo(h, "POST", "/api/identity/register/begin", `{"name":"invited","invite":"`+minted.Token+`"}`, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"sessionId"`) {
		t.Fatalf("invited begin should run the ceremony: got %d %s", rec.Code, rec.Body)
	}
	// the invite is NOT consumed by a begin that never finishes
	if ok, _ := s.inviteGate(minted.Token); !ok {
		t.Fatal("abandoned ceremony must not burn the invite")
	}
}

func TestLockedAdminPersistence(t *testing.T) {
	dir := t.TempDir()
	s := testSession(t, dir)
	h := build(dir, "")
	cookie := sessionCookieFor(s)

	// PUT members mode via the admin API and verify the file layer reflects it
	body := `{"pasteAccess":"members"}`
	rec := adminDo(h, "PUT", "/api/admin/config", body, cookie)
	if rec.Code != 200 {
		t.Fatalf("members put: got %d %s", rec.Code, rec.Body)
	}
	if k := knobOf(t, rec.Body.Bytes(), "PASTE_ACCESS"); k.Source != "file" || k.Value != "members" {
		t.Fatalf("paste access knob must be file members after put: %+v", k)
	}

	// A fresh boot must load the file layer and enforce the lock
	h = build(dir, "")
	if rec = get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":true`) {
		t.Fatalf("fresh boot must see file members mode: %s", rec.Body)
	}
	if rec = adminDo(h, "POST", "/api/paste", fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload()), ""); rec.Code != 403 {
		t.Fatalf("anon create must be locked after reboot: got %d", rec.Code)
	}

	// Clearing the mode via UI persists the unlock
	if rec = adminDo(h, "PUT", "/api/admin/config", `{"pasteAccess":"open"}`, cookie); rec.Code != 200 {
		t.Fatalf("pasteAccess=open put: got %d %s", rec.Code, rec.Body)
	}
	h = build(dir, "")
	if rec = get(h, "/api/gate"); !strings.Contains(rec.Body.String(), `"locked":false`) {
		t.Fatalf("fresh boot must see file open mode: %s", rec.Body)
	}
}
