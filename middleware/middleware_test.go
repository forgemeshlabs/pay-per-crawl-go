package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

const wallet = "0x13C3C28c64cc9d60eEb8a675F3fe27eBC6a4Cd09"

var site = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "SITE") })

func get(h http.Handler, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	h := Handler(paypercrawl.Config{PayTo: wallet}, site)
	if r := get(h, "GPTBot/1.2"); r.Code != 402 || strings.Contains(r.Body.String(), "SITE") || r.Header().Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("bot: %d", r.Code)
	}
	if r := get(h, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"); r.Code != 200 || r.Body.String() != "SITE" {
		t.Fatalf("human: %d", r.Code)
	}
}

func TestNewAndWrap(t *testing.T) {
	if _, err := New(paypercrawl.Config{}, site); err == nil {
		t.Fatal("missing PayTo must error")
	}
	if _, err := Wrap(paypercrawl.Config{PayTo: "bad"}); err == nil {
		t.Fatal("bad PayTo must error")
	}
	mw, err := Wrap(paypercrawl.Config{PayTo: wallet})
	if err != nil {
		t.Fatal(err)
	}
	if r := get(mw(site), "curl/8"); r.Code != 402 {
		t.Fatalf("wrap: %d", r.Code)
	}
}

func TestHandlerPanicsOnBadConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	Handler(paypercrawl.Config{}, site)
}
