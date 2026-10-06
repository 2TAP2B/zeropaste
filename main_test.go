package main

import (
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
