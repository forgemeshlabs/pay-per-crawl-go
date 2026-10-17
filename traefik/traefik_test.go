package traefik

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew(t *testing.T) {
	cfg := CreateConfig()
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "x"); err == nil {
		t.Fatal("missing payTo must error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.PayTo = "0x13C3C28c64cc9d60eEb8a675F3fe27eBC6a4Cd09"
	cfg.BotOverrides = map[string]string{"GPTBot": "block"}
	h, err := New(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), cfg, "x")
	if err != nil {
		t.Fatal(err)
	}
	for ua, want := range map[string]int{"GPTBot/1": 403, "ClaudeBot/1": 402} {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s: %d want %d", ua, rec.Code, want)
		}
	}
}
