package paypercrawl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var payToRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// Paths that are never gated.
var exemptPrefixes = []string{"/robots.txt", "/llms.txt", "/agents.txt", "/.well-known/", "/favicon.ico", "/sitemap"}

// Gate applies the pay-per-crawl policy to HTTP requests. It is the single implementation the
// net/http, Caddy and Traefik adapters all call.
type Gate struct {
	cfg      Config
	cls      *Classifier
	lock     NonceLock
	secret   string
	reporter *Reporter
	cancel   context.CancelFunc
}

// NewGate validates cfg and returns a Gate. In gate mode PayTo must be a 0x EVM address.
func NewGate(cfg Config) (*Gate, error) {
	if cfg.mode() == ModeGate && !payToRe.MatchString(cfg.PayTo) {
		return nil, errors.New("paypercrawl: PayTo must be a 0x-prefixed 20-byte EVM address in gate mode")
	}
	if cfg.PriceUSD < 0 {
		return nil, errors.New("paypercrawl: PriceUSD must be positive")
	}
	g := &Gate{cfg: cfg, cls: NewClassifier(cfg.resolver()), lock: cfg.Lock, secret: cfg.MPPSecret}
	if g.lock == nil {
		g.lock = NewMemoryLock()
	}
	if g.secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		g.secret = hex.EncodeToString(b)
	}
	if cfg.ProKey != "" {
		if !ProEnabled(cfg.ProKey) {
			return nil, errors.New("paypercrawl: ProKey does not look like a ForgeMesh Pro license key (fmppc_...)")
		}
		g.reporter = newReporter(&g.cfg, g.cls)
		ctx, cancel := context.WithCancel(context.Background())
		g.cancel = cancel
		go g.reporter.Run(ctx)
	}
	return g, nil
}

// Close stops the Pro reporter, if any.
func (g *Gate) Close() {
	if g.cancel != nil {
		g.cancel()
	}
}

// Classifier exposes the gate's classifier (catalog merges, tests).
func (g *Gate) Classifier() *Classifier { return g.cls }

// Reporter returns the Pro reporter, or nil when no ProKey is configured.
func (g *Gate) Reporter() *Reporter { return g.reporter }

// Handle runs the gate for one request. It returns true when the request should continue to the
// protected handler (response headers such as PAYMENT-RESPONSE may already be set on w); it
// returns false when it has already written the response (402, 403, or a discovery document).
func (g *Gate) Handle(w http.ResponseWriter, r *http.Request) bool {
	base, host := g.baseURL(r)
	path := r.URL.Path

	if !g.cfg.DisableDiscovery && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if g.serveDiscovery(w, r, strings.TrimRight(path, "/"), base, host) {
			return false
		}
	}
	if g.exempt(path) {
		return true
	}

	h := headerMap(r)
	ip := g.clientIP(r)
	c := g.cls.Classify(h["user-agent"], h, ip)
	hit := Hit{Time: g.cfg.now(), Class: c.Class, BotName: c.Name, Verified: c.Verified, Method: r.Method, Path: path, UA: h["user-agent"]}
	if g.reporter != nil {
		hit.IPHash = g.reporter.HashIP(ip)
	}

	resource := base + r.URL.RequestURI()
	desc := g.siteName(host) + ": one page fetch (HTML)"
	x := g.x402(base, host)
	payment := x.ExtractPayment(h, resource)

	if c.Class == "human" && payment == nil {
		return true
	}
	policy := g.cfg.Policy(c)

	if policy == PolicyFree && payment == nil {
		g.record(hit, "passed", host)
		return true
	}
	if policy == PolicyBlock {
		g.record(hit, "blocked", host)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(`{"error":"forbidden","detail":"This crawler is not permitted on this site."}`))
		}
		return false
	}
	if payment == nil {
		if g.cfg.mode() == ModeMonitor {
			hit.AmountUnits = unitsInt(x.Price())
			g.record(hit, "monitor", host)
			return true
		}
		g.record(hit, "unpaid", host)
		g.write402(w, r, x.Challenge(resource, desc, "", "", ""))
		return false
	}

	// A payment was presented.
	hit.Rail = payment.Rail
	if payment.Error != "" {
		hit.Reason = payment.Error
		g.record(hit, "rejected", host)
		g.write402(w, r, x.Challenge(resource, desc, payment.Error, payment.Detail, payment.Rail))
		return false
	}
	if pre := x.Precheck(payment, resource); pre != "" {
		hit.Reason = pre
		g.record(hit, "rejected", host)
		g.write402(w, r, x.Challenge(resource, desc, pre, "", payment.Rail))
		return false
	}
	auth := payment.Authorization()
	lockKey := "fmppc_nonce_" + strings.ToLower(str(auth["nonce"]))
	if !g.lock.Acquire(lockKey, 15*time.Minute) {
		hit.Reason = "payment_in_flight"
		g.record(hit, "rejected", host)
		g.write402(w, r, x.Challenge(resource, desc, "payment_in_flight", "This authorization was already presented.", payment.Rail))
		return false
	}

	// Detached from the request context: a client hanging up must not abandon a settlement that
	// may already have moved money.
	s := x.VerifyAndSettle(context.Background(), payment, resource)
	if !s.OK {
		if s.Reason == "facilitator_unreachable" {
			g.lock.Release(lockKey) // let the client retry the same authorization
		}
		hit.Reason = s.Reason
		hit.Payer = s.Payer
		if hit.Payer == "" {
			hit.Payer = str(auth["from"])
		}
		g.record(hit, "settle_failed", host)
		g.write402(w, r, x.Challenge(resource, desc, s.Reason, s.Detail, payment.Rail))
		return false
	}

	hit.AmountUnits = bigToInt64(str(auth["value"]))
	hit.Tx, hit.Payer = s.Tx, s.Payer
	if hit.Payer == "" {
		hit.Payer = str(auth["from"])
	}
	g.record(hit, "paid", host)
	raw, _ := marshalNoEscape(s.Raw)
	receipt := base64.StdEncoding.EncodeToString(raw)
	w.Header().Set("PAYMENT-RESPONSE", receipt)
	w.Header().Set("X-PAYMENT-RESPONSE", receipt)
	if payment.Rail == RailMPP {
		w.Header().Set("Payment-Receipt", x.MPPReceipt(s.Tx))
	}
	w.Header().Set("Cache-Control", "private, no-store")
	return true
}

func (g *Gate) record(h Hit, status, host string) {
	h.Status = status
	if g.reporter != nil {
		g.reporter.record(h, host)
	}
	if g.cfg.OnHit != nil {
		g.cfg.OnHit(h)
	}
}

func (g *Gate) x402(base, host string) *X402 {
	realm := g.cfg.Realm
	if realm == "" {
		realm = host
	}
	return NewX402(Params{
		PayTo: g.cfg.PayTo, PriceUSD: g.cfg.price(), FacilitatorURL: g.cfg.FacilitatorURL, FacilitatorAuth: g.cfg.FacilitatorAuth,
		MPPSecret: g.secret, Realm: realm, SiteName: g.siteName(host), ManifestURL: base + "/.well-known/x402.json",
		HTTPClient: g.cfg.httpClient(), Now: g.cfg.now,
	})
}

func (g *Gate) exempt(path string) bool {
	for _, p := range exemptPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	for _, p := range g.cfg.AllowPaths {
		p = strings.TrimSpace(p)
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func (g *Gate) serveDiscovery(w http.ResponseWriter, r *http.Request, path, base, host string) bool {
	var ctype, body string
	switch path {
	case "/.well-known/x402.json":
		raw, _ := json.MarshalIndent(g.Manifest(base, host), "", "    ")
		ctype, body = "application/json; charset=utf-8", string(raw)
	case "/llms.txt":
		ctype, body = "text/plain; charset=utf-8", g.LLMS(base, host)
	case "/agents.txt":
		ctype, body = "text/plain; charset=utf-8", g.Agents(base, host)
	default:
		return false
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	return true
}

// write402 writes a challenge. HEAD gets the same status and headers without a body.
func (g *Gate) write402(w http.ResponseWriter, r *http.Request, c *ChallengeResponse) {
	hd := w.Header()
	for k, v := range c.Headers {
		hd.Set(k, v)
	}
	hd.Set("Content-Type", c.ContentType)
	hd.Set("Content-Length", strconv.Itoa(len(c.Body)))
	w.WriteHeader(c.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(c.Body)
	}
}

func (g *Gate) baseURL(r *http.Request) (base, host string) {
	if b := strings.TrimRight(g.cfg.BaseURL, "/"); b != "" {
		h := b
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		return b, stripPort(h)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if xf := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); xf == "https" || xf == "http" {
		scheme = xf
	}
	return scheme + "://" + r.Host, stripPort(r.Host)
}

func stripPort(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		return hh
	}
	return h
}

func (g *Gate) clientIP(r *http.Request) string {
	if g.cfg.ClientIP != nil {
		if ip := g.cfg.ClientIP(r); ip != "" {
			return ip
		}
	}
	ip := stripPort(r.RemoteAddr)
	if g.cfg.TrustedIPHeader != "" {
		if v := r.Header.Get(g.cfg.TrustedIPHeader); v != "" {
			// Right-most entry: the one appended by the proxy in front of us. The left-most is
			// client-controlled and would let a scraper prepend a Googlebot address.
			parts := strings.Split(v, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if _, err := netip.ParseAddr(last); err == nil {
				ip = last
			}
		}
	}
	return ip
}

func headerMap(r *http.Request) map[string]string {
	m := make(map[string]string, len(r.Header)+1)
	for k, v := range r.Header {
		if len(v) > 0 {
			m[strings.ToLower(k)] = v[0]
		}
	}
	return m
}

func unitsInt(s string) int64 { return bigToInt64(s) }

func bigToInt64(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
