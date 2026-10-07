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
}

func TestRateLimit(t *testing.T) {
	h := build(t.TempDir(), "")
	body := fmt.Sprintf(`{"data":%q,"ttl":"1d"}`, fakePayload())
	// abuse case: POST flood filling the disk — 30/min/IP, then 429
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
		"/api/paste/abcdefgh..", // dot traversal attempt — alphabet check must reject
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
