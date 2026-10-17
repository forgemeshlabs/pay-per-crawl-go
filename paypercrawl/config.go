// Package paypercrawl is the core of ForgeMesh Pay-per-Crawl: it classifies who
// is asking, answers bot traffic with an x402 (v1 + v2) and MPP 402 challenge,
// and serves the page only after the facilitator returns a settlement
// transaction hash. The site owner keeps 100%: there is no custody, account or
// ForgeMesh key in the payment path; the facilitator is called directly.
package paypercrawl

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// Version is reported in User-Agent strings and the discovery manifest.
const Version = "0.1.0"

// Modes.
const (
	ModeGate    = "gate"    // answer 402 to paid classes
	ModeMonitor = "monitor" // classify and log only, never block
)

// Policies for a crawler class or a named bot.
const (
	PolicyFree  = "free"
	PolicyPaid  = "paid"
	PolicyBlock = "block"
)

// Resolver is the slice of *net.Resolver the classifier needs for reverse DNS
// verification of search engines. Inject a fake in tests.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Config configures a Gate. Zero values are safe: Mode defaults to gate,
// FacilitatorURL to PayAI, ClassPolicy to the defaults below.
type Config struct {
	// PayTo is the EVM address that receives the USDC (Base mainnet). Required in gate mode.
	PayTo string
	// PriceUSD is the price of one page fetch. Default 0.01. Keep at or above 0.005.
	PriceUSD float64
	// Mode is "gate" (default) or "monitor".
	Mode string
	// FacilitatorURL defaults to https://facilitator.payai.network (v1 and v2, Base mainnet, no key).
	FacilitatorURL string
	// FacilitatorAuth, when set, is sent as the Authorization header to the facilitator.
	FacilitatorAuth string
	// ClassPolicy maps a crawler class (human, search, social, monitor, seo, ai,
	// automation, bot) to free, paid or block. Unlisted classes follow DefaultClassPolicy.
	ClassPolicy map[string]string
	// BotOverrides maps a bot name from the catalog (for example "GPTBot") to free, paid or block.
	BotOverrides map[string]string
	// AllowPaths are path prefixes that are never gated.
	AllowPaths []string
	// TrustedIPHeader, when set (for example "X-Forwarded-For" or "CF-Connecting-IP"),
	// is read for the client IP used in search-engine verification. Only set it when
	// that header is overwritten or appended to by your own proxy. For a multi-value header
	// (X-Forwarded-For) the RIGHT-MOST entry is used, never the client-controlled left-most.
	TrustedIPHeader string
	// ClientIP, if set, returns the client IP for a request and takes precedence over
	// TrustedIPHeader (the Caddy adapter uses it to honour Caddy's trusted_proxies).
	ClientIP func(*http.Request) string
	// ProKey is the optional ForgeMesh Pro license key (fmppc_...). Without it nothing calls out
	// except the facilitator.
	ProKey string

	// BaseURL pins the public origin used in challenges (for example "https://example.com").
	// Default: derived from the request (TLS, X-Forwarded-Proto, Host).
	BaseURL string
	// SiteName appears in challenge descriptions and discovery documents.
	SiteName string
	// SiteDescription appears in llms.txt and the manifest.
	SiteDescription string
	// Contact, if set, is published in the manifest.
	Contact string
	// Realm is the MPP realm. Defaults to the request host.
	Realm string
	// MPPSecret keys the stateless MPP challenge binding. If empty a random one is
	// generated at start (challenges then do not survive a restart or span instances).
	MPPSecret string
	// DisableDiscovery turns off /.well-known/x402.json, /llms.txt and /agents.txt.
	DisableDiscovery bool

	// HTTPClient is used for facilitator and Pro calls. Defaults to a 45 s client.
	HTTPClient *http.Client
	// Lock is the nonce replay lock. Defaults to an in-memory lock.
	Lock NonceLock
	// Resolver is used for reverse DNS. Defaults to net.DefaultResolver.
	Resolver Resolver
	// OnHit, if set, is called for every classified non-human request outcome.
	OnHit func(Hit)
	// ProBase overrides https://proxy.forgemesh.io (tests).
	ProBase string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// DefaultClassPolicy is the out-of-the-box policy: humans, verified search
// engines, link previews and uptime monitors are free; AI, SEO, automation and
// unknown bots pay.
var DefaultClassPolicy = map[string]string{
	"human": PolicyFree, "search": PolicyFree, "social": PolicyFree, "monitor": PolicyFree,
	"seo": PolicyPaid, "ai": PolicyPaid, "automation": PolicyPaid, "bot": PolicyPaid,
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) price() float64 {
	if c.PriceUSD <= 0 {
		return 0.01
	}
	return c.PriceUSD
}

func (c *Config) mode() string {
	if strings.EqualFold(c.Mode, ModeMonitor) {
		return ModeMonitor
	}
	return ModeGate
}

func (c *Config) facilitatorURL() string {
	u := strings.TrimSpace(c.FacilitatorURL)
	if u == "" {
		u = DefaultFacilitator
	}
	return strings.TrimRight(u, "/")
}

func (c *Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 45 * time.Second}
}

func (c *Config) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

// Policy returns free, paid or block for a classification.
func (c *Config) Policy(cl Classification) string {
	if cl.Name != "" {
		if p, ok := c.BotOverrides[cl.Name]; ok && validPolicy(p) {
			return p
		}
	}
	if p, ok := c.ClassPolicy[cl.Class]; ok && validPolicy(p) {
		return p
	}
	if p, ok := DefaultClassPolicy[cl.Class]; ok {
		return p
	}
	return PolicyPaid
}

func validPolicy(p string) bool { return p == PolicyFree || p == PolicyPaid || p == PolicyBlock }
