package paypercrawl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type proServer struct {
	mu     sync.Mutex
	auths  []string
	ingest []map[string]any
	srv    *httptest.Server
	active bool
}

func newProServer(t *testing.T) *proServer {
	p := &proServer{active: true}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.auths = append(p.auths, r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/wp/license/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": p.active, "status": "active"})
		case "/api/wp/ingest":
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			p.ingest = append(p.ingest, m)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/api/wp/intel":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v1", "agents": []any{
				map[string]any{"name": "Brand New Crawler", "class": "seo", "match": []string{"BrandNewCrawler/"}},
				map[string]any{"name": "Bad Class", "class": "nonsense", "match": []string{"bad"}},
			}})
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

const testProKey = "fmppc_abcdefghijklmnopqrstuvwxyz0123"

func TestProReporter(t *testing.T) {
	pro := newProServer(t)
	r := newRig(t, func(c *Config) { c.ProKey = testProKey; c.ProBase = pro.srv.URL })
	x := testX402(t, "")
	r.do("GET", "/a", gptUA, nil)
	r.do("GET", "/b", gptUA, map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('p'))})
	r.do("GET", "/c", "Scrapy/2", nil)
	if err := r.gate.Reporter().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	pro.mu.Lock()
	defer pro.mu.Unlock()
	for _, a := range pro.auths {
		if a != "Bearer "+testProKey {
			t.Fatalf("auth header %q", a)
		}
	}
	if len(pro.ingest) != 1 {
		t.Fatalf("ingest calls: %d", len(pro.ingest))
	}
	in := pro.ingest[0]
	site := in["site"].(map[string]any)
	if site["host"] != "127.0.0.1" || site["pay_to"] != testPayTo || site["mode"] != "gate" || site["plugin_version"] != Version {
		t.Fatalf("site: %v", site)
	}
	sets := in["settlements"].([]any)
	if len(sets) != 1 || sets[0].(map[string]any)["tx_hash"] != "0xtx1" || sets[0].(map[string]any)["amount_units"].(float64) != 10000 {
		t.Fatalf("settlements: %v", sets)
	}
	var gpt map[string]any
	for _, row := range in["daily"].([]any)[0].(map[string]any)["rows"].([]any) {
		if row.(map[string]any)["bot_name"] == "GPTBot" {
			gpt = row.(map[string]any)
		}
	}
	if gpt["hits"].(float64) != 2 || gpt["paid"].(float64) != 1 || gpt["unpaid"].(float64) != 1 || gpt["revenue_units"].(float64) != 10000 || gpt["sources"].(float64) != 1 {
		t.Fatalf("gpt rollup: %v", gpt)
	}
	// Intel was merged (valid entry added, invalid class dropped).
	if g := r.gate.Classifier().Classify("brandnewcrawler/2", nil, ""); g.Class != "seo" {
		t.Fatalf("intel not merged: %+v", g)
	}
	if g := r.gate.Classifier().Classify("bad/2", nil, ""); g.Name == "Bad Class" {
		t.Fatal("invalid intel class accepted")
	}
}

func TestProSettlementsSentOnce(t *testing.T) {
	pro := newProServer(t)
	r := newRig(t, func(c *Config) { c.ProKey = testProKey; c.ProBase = pro.srv.URL })
	x := testX402(t, "")
	r.do("GET", "/b", gptUA, map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('q'))})
	_ = r.gate.Reporter().Sync(context.Background())
	_ = r.gate.Reporter().Sync(context.Background())
	pro.mu.Lock()
	defer pro.mu.Unlock()
	if n := len(pro.ingest[1]["settlements"].([]any)); n != 0 {
		t.Fatalf("settlement re-sent: %d", n)
	}
}

func TestProInactiveLicenseSendsNothing(t *testing.T) {
	pro := newProServer(t)
	pro.active = false
	r := newRig(t, func(c *Config) { c.ProKey = testProKey; c.ProBase = pro.srv.URL })
	r.do("GET", "/a", gptUA, nil)
	if err := r.gate.Reporter().Sync(context.Background()); err == nil {
		t.Fatal("expected license error")
	}
	if len(pro.ingest) != 0 {
		t.Fatal("ingest called with an inactive license")
	}
}

func TestNoProKeyNoCalls(t *testing.T) {
	r := newRig(t, nil)
	if r.gate.Reporter() != nil {
		t.Fatal("no reporter without a key")
	}
}

func TestProEnabledShape(t *testing.T) {
	if !ProEnabled(testProKey) || ProEnabled("nope") || ProEnabled("fmppc_short") {
		t.Fatal("key shape")
	}
}
