package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

const wallet = "0x13C3C28c64cc9d60eEb8a675F3fe27eBC6a4Cd09"

func parse(t *testing.T, src string) *Handler {
	t.Helper()
	h := &Handler{}
	if err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(src)); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCaddyfileParse(t *testing.T) {
	h := parse(t, `pay_per_crawl {
		pay_to `+wallet+`
		price 0.02
		mode monitor
		facilitator https://f.example
		facilitator_auth "Bearer k"
		policy ai block
		policy seo free
		bot GPTBot free
		allow_path /a/
		allow_path /b/
		trusted_ip_header CF-Connecting-IP
		pro_key fmppc_x
		site_name "My Site"
		site_description "desc"
		contact hi@example.com
		realm example.com
		mpp_secret s3
		base_url https://example.com
		discovery off
	}`)
	if h.PayTo != wallet || h.PriceUSD != 0.02 || h.Mode != "monitor" || h.FacilitatorURL != "https://f.example" || h.FacilitatorAuth != "Bearer k" ||
		h.ClassPolicy["ai"] != "block" || h.ClassPolicy["seo"] != "free" || h.BotOverrides["GPTBot"] != "free" || len(h.AllowPaths) != 2 ||
		h.TrustedIPHeader != "CF-Connecting-IP" || h.ProKey != "fmppc_x" || h.SiteName != "My Site" || h.Realm != "example.com" ||
		h.MPPSecret != "s3" || h.BaseURL != "https://example.com" || !h.DisableDiscovery || h.Contact != "hi@example.com" || h.SiteDescription != "desc" {
		t.Fatalf("%+v", h)
	}
	if h := parse(t, "pay_per_crawl "+wallet); h.PayTo != wallet {
		t.Fatal("inline pay_to")
	}
	for _, bad := range []string{"pay_per_crawl {\n bogus 1\n}", "pay_per_crawl {\n price abc\n}", "pay_per_crawl {\n policy ai\n}", "pay_per_crawl {\n discovery maybe\n}"} {
		if err := (&Handler{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	if (&Handler{}).Validate() == nil {
		t.Fatal("gate mode without pay_to must fail")
	}
	if (&Handler{Mode: "monitor"}).Validate() != nil || (&Handler{PayTo: wallet}).Validate() != nil {
		t.Fatal("valid configs rejected")
	}
	if (&Handler{PayTo: wallet, Mode: "weird"}).Validate() == nil {
		t.Fatal("bad mode accepted")
	}
}

func TestServeHTTP(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	t.Setenv("PPC_TEST_PAYTO", wallet)
	h := &Handler{PayTo: "{env.PPC_TEST_PAYTO}"}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.Cleanup()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, _ = io.WriteString(w, "SITE")
		return nil
	})
	do := func(ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://example.com/post/", nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		if err := h.ServeHTTP(rec, req, next); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	r := do("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)")
	if r.Code != 402 || r.Header().Get("PAYMENT-REQUIRED") == "" || !strings.Contains(r.Body.String(), `"payTo":"`+wallet+`"`) || strings.Contains(r.Body.String(), "SITE") {
		t.Fatalf("bot: %d %s", r.Code, r.Body)
	}
	r = do("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36")
	if r.Code != 200 || r.Body.String() != "SITE" {
		t.Fatalf("human: %d %s", r.Code, r.Body)
	}
	// Bad config surfaces at provision time.
	if err := (&Handler{PayTo: "nope"}).Provision(ctx); err == nil {
		t.Fatal("expected provision error for bad pay_to")
	}
}

func TestAdaptExampleCaddyfile(t *testing.T) {
	src, err := os.ReadFile("../examples/caddy/Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	m := adapt(t, string(src))
	raw, _ := json.Marshal(m)
	if !strings.Contains(string(raw), `"handler":"pay_per_crawl"`) || !strings.Contains(string(raw), `"bot_overrides":{"Bytespider":"block"`) {
		t.Fatalf("example Caddyfile did not adapt to the module: %s", raw)
	}
}

func adapt(t *testing.T, cf string) map[string]any {
	t.Helper()
	ad := caddyconfig.GetAdapter("caddyfile")
	if ad == nil {
		t.Fatal("caddyfile adapter missing")
	}
	out, warns, err := ad.Adapt([]byte(cf), nil)
	if err != nil {
		t.Fatalf("adapt: %v (%v)", err, warns)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDirectiveOrderBeforeReverseProxy(t *testing.T) {
	m := adapt(t, `example.com {
		reverse_proxy localhost:9
		pay_per_crawl `+wallet+`
	}`)
	raw, _ := json.Marshal(m)
	s := string(raw)
	i, j := strings.Index(s, `"http.handlers.pay_per_crawl"`), strings.Index(s, `"reverse_proxy"`)
	if i < 0 {
		i = strings.Index(s, `"handler":"pay_per_crawl"`)
	}
	if i < 0 || j < 0 || i > j {
		t.Fatalf("gate must run before reverse_proxy regardless of Caddyfile order (%d, %d): %s", i, j, s)
	}
}
