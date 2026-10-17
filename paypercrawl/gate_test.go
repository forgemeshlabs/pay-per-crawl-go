package paypercrawl

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	gptUA  = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	humUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
	pageOK = "ZZPAIDZZ"
)

type rig struct {
	t    *testing.T
	fac  *mockFacilitator
	gate *Gate
	srv  *httptest.Server
	mu   sync.Mutex
	hits []Hit
}

func newRig(t *testing.T, mut func(*Config)) *rig {
	r := &rig{t: t, fac: newMockFacilitator(t)}
	cfg := Config{PayTo: testPayTo, PriceUSD: 0.01, FacilitatorURL: r.fac.srv.URL, MPPSecret: "gate-secret", SiteName: "Example",
		OnHit: func(h Hit) { r.mu.Lock(); r.hits = append(r.hits, h); r.mu.Unlock() }}
	if mut != nil {
		mut(&cfg)
	}
	g, err := NewGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	r.gate = g
	r.srv = httptest.NewServer(g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "<html>"+pageOK+"</html>")
	})))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) do(method, path, ua string, hdr map[string]string) (*http.Response, string) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.srv.URL+path, nil)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (r *rig) lastStatus() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.hits) == 0 {
		return ""
	}
	return r.hits[len(r.hits)-1].Status
}

func TestGateUnpaidBotGets402(t *testing.T) {
	r := newRig(t, nil)
	resp, body := r.do("GET", "/post/?x=1", gptUA, nil)
	if resp.StatusCode != 402 || strings.Contains(body, pageOK) {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp.Header.Get("PAYMENT-REQUIRED"))
	var env map[string]any
	_ = json.Unmarshal(raw, &env)
	if env["resource"].(map[string]any)["url"] != r.srv.URL+"/post/?x=1" {
		t.Fatalf("resource url: %s", raw)
	}
	if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Payment ") || r.lastStatus() != "unpaid" {
		t.Fatal("MPP header / hit log")
	}
	if len(r.fac.snapshot()) != 0 {
		t.Fatal("an unpaid request must not touch the facilitator")
	}
}

func TestGateHeadIs402LikeGet(t *testing.T) {
	r := newRig(t, nil)
	resp, body := r.do("HEAD", "/post/", gptUA, nil)
	if resp.StatusCode != 402 || body != "" || resp.Header.Get("PAYMENT-REQUIRED") == "" || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("HEAD: status %d body %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Length") == "0" {
		t.Fatal("HEAD should advertise the GET body length")
	}
}

func TestGateFreeClasses(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Resolver = fakeResolver{} }) // no PTR for anyone
	for _, ua := range []string{humUA, "facebookexternalhit/1.1", "UptimeRobot/2.0"} {
		if resp, body := r.do("GET", "/", ua, map[string]string{"Accept": "text/html"}); resp.StatusCode != 200 || !strings.Contains(body, pageOK) {
			t.Errorf("%s: %d", ua, resp.StatusCode)
		}
	}
	// Unverified Googlebot (claim kept: loopback has no PTR in tests -> definite no -> demoted).
	if resp, _ := r.do("GET", "/", "Googlebot/2.1", nil); resp.StatusCode != 402 {
		t.Errorf("googlebot from a non-Google IP must be demoted and charged, got %d", resp.StatusCode)
	}
}

func TestGateVerifiedSearchEngineFree(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.Resolver = fakeResolver{ptr: map[string][]string{"127.0.0.1": {"crawl.googlebot.com"}}, fwd: map[string][]string{"crawl.googlebot.com": {"127.0.0.1"}}}
	})
	if resp, body := r.do("GET", "/", "Googlebot/2.1", nil); resp.StatusCode != 200 || !strings.Contains(body, pageOK) {
		t.Fatalf("verified Googlebot: %d", resp.StatusCode)
	}
}

func TestGateTrustedIPHeader(t *testing.T) {
	res := fakeResolver{ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com"}}, fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}}}
	r := newRig(t, func(c *Config) { c.Resolver = res; c.TrustedIPHeader = "X-Forwarded-For" })
	if resp, _ := r.do("GET", "/", "Googlebot/2.1", map[string]string{"X-Forwarded-For": "10.0.0.1, 66.249.66.1"}); resp.StatusCode != 200 {
		t.Fatalf("trusted header should verify: %d", resp.StatusCode)
	}
	r2 := newRig(t, func(c *Config) { c.Resolver = res }) // header not trusted -> spoof ignored
	if resp, _ := r2.do("GET", "/", "Googlebot/2.1", map[string]string{"X-Forwarded-For": "66.249.66.1"}); resp.StatusCode != 402 {
		t.Fatalf("untrusted header must be ignored: %d", resp.StatusCode)
	}
}

func TestGatePaidV2(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	resp, body := r.do("GET", "/post/", gptUA, map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('a'))})
	if resp.StatusCode != 200 || !strings.Contains(body, pageOK) {
		t.Fatalf("paid v2: %d %s", resp.StatusCode, body)
	}
	rec, _ := base64.StdEncoding.DecodeString(resp.Header.Get("PAYMENT-RESPONSE"))
	if !strings.Contains(string(rec), `"transaction":"0xtx1"`) || resp.Header.Get("X-PAYMENT-RESPONSE") != resp.Header.Get("PAYMENT-RESPONSE") {
		t.Fatalf("receipts: %s", rec)
	}
	if resp.Header.Get("Cache-Control") != "private, no-store" || resp.Header.Get("Payment-Receipt") != "" {
		t.Fatal("headers")
	}
	r.mu.Lock()
	h := r.hits[len(r.hits)-1]
	r.mu.Unlock()
	if h.Status != "paid" || h.Tx != "0xtx1" || h.AmountUnits != 10000 || h.Rail != RailV2 || h.BotName != "GPTBot" {
		t.Fatalf("hit: %+v", h)
	}
}

func TestGatePaidV1AndMPP(t *testing.T) {
	r := newRig(t, nil)
	resp, body := r.do("GET", "/", "x402-fetch/1.2.0", map[string]string{"X-PAYMENT": v1Header(nonceN('b'))})
	if resp.StatusCode != 200 || !strings.Contains(body, pageOK) || resp.Header.Get("X-PAYMENT-RESPONSE") == "" {
		t.Fatalf("v1: %d", resp.StatusCode)
	}
	if b := r.fac.snapshot()[0].Body; b["x402Version"].(float64) != 1 {
		t.Fatal("v1 not forwarded as v1")
	}
	// MPP: fetch a real challenge from the gate, answer it, retry.
	ch, _ := r.do("GET", "/mpp", "curl/8", nil)
	// The realm is the request host (127.0.0.1) and mppHeader builds the nonce from it.
	cred := mppHeader(t, ch.Header.Get("WWW-Authenticate"), nil)
	resp, body = r.do("GET", "/mpp", "curl/8", map[string]string{"Authorization": cred})
	if resp.StatusCode != 200 || !strings.Contains(body, pageOK) || resp.Header.Get("Payment-Receipt") == "" {
		t.Fatalf("mpp: %d %s", resp.StatusCode, body)
	}
	rc, _ := base64.RawURLEncoding.DecodeString(resp.Header.Get("Payment-Receipt"))
	if !strings.Contains(string(rc), `"reference":"0xtx1"`) {
		t.Fatalf("receipt %s", rc)
	}
}

func TestGateReplayLock(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	h := map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('c'))}
	if resp, _ := r.do("GET", "/", gptUA, h); resp.StatusCode != 200 {
		t.Fatal("first use")
	}
	resp, body := r.do("GET", "/", gptUA, h)
	if resp.StatusCode != 402 || !strings.Contains(body, "payment_in_flight") {
		t.Fatalf("replay must be refused: %d %s", resp.StatusCode, body)
	}
	if n := len(r.fac.snapshot()); n != 2 {
		t.Fatalf("replay reached the facilitator: %d calls", n)
	}
}

func TestGateFacilitatorOutageReleasesLock(t *testing.T) {
	r := newRig(t, func(c *Config) { c.FacilitatorURL = "http://127.0.0.1:1" })
	x := testX402(t, "")
	h := map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('d'))}
	for i := 0; i < 2; i++ {
		resp, body := r.do("GET", "/", gptUA, h)
		if resp.StatusCode != 402 || !strings.Contains(body, "facilitator_unreachable") {
			t.Fatalf("attempt %d: %d %s", i, resp.StatusCode, body)
		}
	}
	if r.lastStatus() != "settle_failed" {
		t.Fatal(r.lastStatus())
	}
}

func TestGateSettleFailuresNeverServe(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	r.fac.mu.Lock()
	r.fac.settle = map[string]any{"success": true, "transaction": ""}
	r.fac.mu.Unlock()
	resp, body := r.do("GET", "/", gptUA, map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('e'))})
	if resp.StatusCode != 402 || strings.Contains(body, pageOK) || !strings.Contains(body, "settlement_failed") {
		t.Fatalf("empty tx served content: %d %s", resp.StatusCode, body)
	}
	r.fac.mu.Lock()
	r.fac.verify = map[string]any{"isValid": false, "invalidReason": "insufficient_funds"}
	r.fac.mu.Unlock()
	resp, body = r.do("GET", "/", gptUA, map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('f'))})
	var b map[string]any
	_ = json.Unmarshal([]byte(body), &b)
	if resp.StatusCode != 402 || b["invalidReason"] != "insufficient_funds" {
		t.Fatalf("invalidReason not surfaced: %s", body)
	}
	raw, _ := base64.StdEncoding.DecodeString(resp.Header.Get("PAYMENT-REQUIRED"))
	if !strings.Contains(string(raw), "insufficient_funds") {
		t.Fatal("envelope error")
	}
}

func TestGatePrecheckRejectsBeforeFacilitator(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	hdr := enc(map[string]any{"x402Version": 2, "accepted": x.RequirementsV2("u"),
		"payload": map[string]any{"signature": "0xs", "authorization": func() map[string]any { a := authz(nonceN('1')); a["to"] = "0x" + strings.Repeat("9", 40); return a }()}})
	resp, body := r.do("GET", "/", gptUA, map[string]string{"PAYMENT-SIGNATURE": hdr})
	if resp.StatusCode != 402 || !strings.Contains(body, "wrong_pay_to") || len(r.fac.snapshot()) != 0 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	resp, body = r.do("GET", "/", gptUA, map[string]string{"PAYMENT-SIGNATURE": "garbage"})
	if resp.StatusCode != 402 || !strings.Contains(body, "malformed_payment_signature") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestGateMonitorMode(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Mode = ModeMonitor })
	resp, body := r.do("GET", "/", gptUA, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, pageOK) || r.lastStatus() != "monitor" {
		t.Fatalf("monitor mode must pass and log: %d %s", resp.StatusCode, r.lastStatus())
	}
	r.mu.Lock()
	amt := r.hits[0].AmountUnits
	r.mu.Unlock()
	if amt != 10000 {
		t.Fatalf("would-have-earned %d", amt)
	}
	// Monitor mode needs no PayTo.
	if _, err := NewGate(Config{Mode: ModeMonitor}); err != nil {
		t.Fatal(err)
	}
}

func TestGatePolicyOverridesAndAllowPaths(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.BotOverrides = map[string]string{"GPTBot": "block", "curl": "free"}
		c.AllowPaths = []string{"/public/"}
	})
	if resp, body := r.do("GET", "/", gptUA, nil); resp.StatusCode != 403 || !strings.Contains(body, "forbidden") {
		t.Fatalf("block: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/", "curl/8.5", nil); resp.StatusCode != 200 {
		t.Fatalf("free override: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/public/a.html", "Scrapy/2", nil); resp.StatusCode != 200 {
		t.Fatalf("allow path: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/private/a.html", "Scrapy/2", nil); resp.StatusCode != 402 {
		t.Fatalf("non-allowed path: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/robots.txt", "Scrapy/2", nil); resp.StatusCode != 200 {
		t.Fatalf("robots.txt is never gated: %d", resp.StatusCode)
	}
}

func TestGatePaymentOnFreeClassIsHonoured(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	resp, _ := r.do("GET", "/", humUA, map[string]string{"Accept": "text/html", "PAYMENT-SIGNATURE": v2Header(x, nonceN('7'))})
	if resp.StatusCode != 200 || r.lastStatus() != "paid" {
		t.Fatalf("%d %s", resp.StatusCode, r.lastStatus())
	}
}

func TestGateConcurrentSameNonceSettlesOnce(t *testing.T) {
	r := newRig(t, nil)
	x := testX402(t, "")
	h := map[string]string{"PAYMENT-SIGNATURE": v2Header(x, nonceN('8'))}
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := r.do("GET", "/", gptUA, h)
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	ok := 0
	for c := range codes {
		if c == 200 {
			ok++
		}
	}
	settles := 0
	for _, c := range r.fac.snapshot() {
		if c.Path == "/settle" {
			settles++
		}
	}
	if ok != 1 || settles != 1 {
		t.Fatalf("one authorization must settle exactly once: served %d, settles %d", ok, settles)
	}
}

func TestNewGateValidation(t *testing.T) {
	for _, c := range []Config{{}, {PayTo: "0x123"}, {PayTo: testPayTo, ProKey: "nope"}} {
		if _, err := NewGate(c); err == nil {
			t.Errorf("expected error for %+v", c)
		}
	}
	if _, err := NewHandler(Config{PayTo: testPayTo}, http.NotFoundHandler()); err != nil {
		t.Fatal(err)
	}
}

func TestDiscovery(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SiteDescription = "A test site"; c.Contact = "hello@example.test" })
	resp, body := r.do("GET", "/.well-known/x402.json", "curl/8", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("manifest: %d", resp.StatusCode)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	res := m["resources"].([]any)[0].(map[string]any)
	acc := res["accepts"].([]any)[0].(map[string]any)
	meta := res["metadata"].(map[string]any)
	if m["x402Version"].(float64) != 2 || acc["payTo"] != testPayTo || acc["amount"] != "10000" || acc["network"] != "eip155:8453" ||
		meta["paid"] != true || meta["priceUsd"].(float64) != 0.01 || m["provider"].(map[string]any)["contact"] != "hello@example.test" ||
		!strings.HasPrefix(res["resource"].(string), r.srv.URL) {
		t.Fatalf("manifest: %s", body)
	}
	_, llms := r.do("GET", "/llms.txt", "curl/8", nil)
	if !strings.Contains(llms, "HTTP 402") || !strings.Contains(llms, "$0.01 USDC") || !strings.Contains(llms, "/.well-known/x402.json") || !strings.Contains(llms, "> A test site") {
		t.Fatalf("llms.txt: %s", llms)
	}
	_, agents := r.do("GET", "/agents.txt", "curl/8", nil)
	if !strings.Contains(agents, "Payments: required") || !strings.Contains(agents, "PayTo: "+testPayTo) || !strings.Contains(agents, "Network: eip155:8453") {
		t.Fatalf("agents.txt: %s", agents)
	}
	if resp, body := r.do("HEAD", "/llms.txt", "curl/8", nil); resp.StatusCode != 200 || body != "" {
		t.Fatalf("HEAD llms: %d", resp.StatusCode)
	}
	if !strings.Contains(r.gate.RobotsAppend(r.srv.URL), "Manifest: "+r.srv.URL+"/.well-known/x402.json") {
		t.Fatal("robots lines")
	}
	// Monitor mode says charging is off.
	m2 := newRig(t, func(c *Config) { c.Mode = ModeMonitor })
	_, llms = m2.do("GET", "/llms.txt", "curl/8", nil)
	_, ag := m2.do("GET", "/agents.txt", "curl/8", nil)
	if !strings.Contains(llms, "charging is not enabled") || !strings.Contains(ag, "Payments: none") {
		t.Fatal("monitor-mode discovery")
	}
	// Disabled: falls through to the site (and is not gated either).
	d := newRig(t, func(c *Config) { c.DisableDiscovery = true })
	if _, b := d.do("GET", "/llms.txt", "curl/8", nil); !strings.Contains(b, pageOK) {
		t.Fatal("disabled discovery should fall through to the site")
	}
}

func TestBaseURLOverrideAndForwardedProto(t *testing.T) {
	r := newRig(t, func(c *Config) { c.BaseURL = "https://shop.example.test/"; c.Realm = "" })
	resp, _ := r.do("GET", "/p", gptUA, nil)
	raw, _ := base64.StdEncoding.DecodeString(resp.Header.Get("PAYMENT-REQUIRED"))
	if !strings.Contains(string(raw), `"url":"https://shop.example.test/p"`) || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `realm="shop.example.test"`) {
		t.Fatalf("%s %s", raw, resp.Header.Get("WWW-Authenticate"))
	}
	r2 := newRig(t, nil)
	resp, _ = r2.do("GET", "/p", gptUA, map[string]string{"X-Forwarded-Proto": "https"})
	raw, _ = base64.StdEncoding.DecodeString(resp.Header.Get("PAYMENT-REQUIRED"))
	if !strings.Contains(string(raw), `"url":"https://127.0.0.1:`) {
		t.Fatalf("%s", raw)
	}
}

func TestTrustedIPHeaderRightMostWins(t *testing.T) {
	res := fakeResolver{ptr: map[string][]string{"66.249.66.1": {"crawl.googlebot.com"}}, fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}}}
	r := newRig(t, func(c *Config) { c.Resolver = res; c.TrustedIPHeader = "X-Forwarded-For" })
	// Scraper prepends a Googlebot IP; the proxy appended the scraper's real address.
	resp, _ := r.do("GET", "/", "Googlebot/2.1", map[string]string{"X-Forwarded-For": "66.249.66.1, 203.0.113.9"})
	if resp.StatusCode != 402 {
		t.Fatalf("spoofed left-most XFF got the free lane: %d", resp.StatusCode)
	}
	r.mu.Lock()
	h := r.hits[len(r.hits)-1]
	r.mu.Unlock()
	if h.Class != "automation" || h.Verified != VerifiedNo {
		t.Fatalf("want automation/impostor, got %+v", h)
	}
	// Single-value edge header is taken as-is.
	r2 := newRig(t, func(c *Config) { c.Resolver = res; c.TrustedIPHeader = "CF-Connecting-IP" })
	if resp, _ := r2.do("GET", "/", "Googlebot/2.1", map[string]string{"CF-Connecting-IP": "66.249.66.1"}); resp.StatusCode != 200 {
		t.Fatalf("single-value header: %d", resp.StatusCode)
	}
}

func TestExemptAnchored(t *testing.T) {
	g := &Gate{cfg: Config{AllowPaths: []string{"/pricing"}}}
	cases := map[string]bool{
		"/robots.txt": true, "/robots.txt.html": false, "/robots.txt.anything": false,
		"/llms.txt": true, "/llms.txtx": false, "/agents.txt": true, "/favicon.ico": true,
		"/sitemap.xml": true, "/wp-sitemap-posts-post-1.xml": true, "/sitemap_index.xml": true,
		"/sitemapfoo": false, "/sitemap.xml/x": false, "/a/sitemap.xml": false,
		"/.well-known/x402.json": true, "/.well-known/../post": false, "/.well-known/%2e%2e/post": false,
		"/.well-known/%2E%2E/post": false, "/foo%2fbar": false,
		"/pricing": true, "/pricing/": true, "/pricing/plans": true, "/pricing-secret": false,
		"//robots.txt": false, "/post": false, "/": false,
	}
	for p, want := range cases {
		if got := g.exempt(p); got != want {
			t.Errorf("exempt(%q) = %v, want %v", p, got, want)
		}
	}
	g2 := &Gate{cfg: Config{AllowPaths: []string{"/docs/"}}}
	if !g2.exempt("/docs/a") || g2.exempt("/docs") || g2.exempt("/docsx") {
		t.Error("trailing-slash AllowPath semantics wrong")
	}
}
