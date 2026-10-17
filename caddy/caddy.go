// Package caddy is the Caddy 2 adapter for ForgeMesh Pay-per-Crawl.
//
// Build:  xcaddy build --with github.com/forgemeshlabs/pay-per-crawl-go/caddy
//
// Caddyfile:
//
//	example.com {
//	    pay_per_crawl {
//	        pay_to {env.PAY_TO}
//	    }
//	    reverse_proxy localhost:8080
//	}
package caddy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

func init() {
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("pay_per_crawl", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("pay_per_crawl", httpcaddyfile.Before, "header")
}

// Shared across config reloads so a reload neither forgets in-flight nonces nor invalidates
// outstanding MPP challenges when no mpp_secret is configured.
var (
	sharedLock    = paypercrawl.NewMemoryLock()
	processSecret = func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}()
)

// Handler is the http.handlers.pay_per_crawl module.
type Handler struct {
	PayTo            string            `json:"pay_to,omitempty"`
	PriceUSD         float64           `json:"price_usd,omitempty"`
	Mode             string            `json:"mode,omitempty"`
	FacilitatorURL   string            `json:"facilitator_url,omitempty"`
	FacilitatorAuth  string            `json:"facilitator_auth,omitempty"`
	ClassPolicy      map[string]string `json:"class_policy,omitempty"`
	BotOverrides     map[string]string `json:"bot_overrides,omitempty"`
	AllowPaths       []string          `json:"allow_paths,omitempty"`
	TrustedIPHeader  string            `json:"trusted_ip_header,omitempty"`
	ProKey           string            `json:"pro_key,omitempty"`
	SiteName         string            `json:"site_name,omitempty"`
	SiteDescription  string            `json:"site_description,omitempty"`
	Contact          string            `json:"contact,omitempty"`
	Realm            string            `json:"realm,omitempty"`
	MPPSecret        string            `json:"mpp_secret,omitempty"`
	BaseURL          string            `json:"base_url,omitempty"`
	DisableDiscovery bool              `json:"disable_discovery,omitempty"`

	gate *paypercrawl.Gate
}

// CaddyModule implements caddy.Module.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.pay_per_crawl",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner. Values may use Caddy placeholders such as {env.PAY_TO}.
func (h *Handler) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	rp := repl.ReplaceAll
	cfg := paypercrawl.Config{
		PayTo:            rp(h.PayTo, ""),
		PriceUSD:         h.PriceUSD,
		Mode:             h.Mode,
		FacilitatorURL:   rp(h.FacilitatorURL, ""),
		FacilitatorAuth:  rp(h.FacilitatorAuth, ""),
		ClassPolicy:      h.ClassPolicy,
		BotOverrides:     h.BotOverrides,
		AllowPaths:       h.AllowPaths,
		TrustedIPHeader:  h.TrustedIPHeader,
		ProKey:           rp(h.ProKey, ""),
		SiteName:         h.SiteName,
		SiteDescription:  h.SiteDescription,
		Contact:          h.Contact,
		Realm:            h.Realm,
		MPPSecret:        rp(h.MPPSecret, ""),
		BaseURL:          h.BaseURL,
		DisableDiscovery: h.DisableDiscovery,
		Lock:             sharedLock,
		ClientIP: func(r *http.Request) string {
			// Caddy resolves this through trusted_proxies; it is the real client address.
			if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
				return v
			}
			return ""
		},
	}
	if cfg.MPPSecret == "" {
		cfg.MPPSecret = processSecret
	}
	g, err := paypercrawl.NewGate(cfg)
	if err != nil {
		return err
	}
	h.gate = g
	return nil
}

// Cleanup implements caddy.CleanerUpper.
func (h *Handler) Cleanup() error {
	if h.gate != nil {
		h.gate.Close()
	}
	return nil
}

// Validate implements caddy.Validator.
func (h *Handler) Validate() error {
	if strings.EqualFold(h.Mode, paypercrawl.ModeMonitor) {
		return nil
	}
	if h.Mode != "" && !strings.EqualFold(h.Mode, paypercrawl.ModeGate) {
		return fmt.Errorf("mode must be gate or monitor, got %q", h.Mode)
	}
	if h.PayTo == "" {
		return fmt.Errorf("pay_to is required in gate mode")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !h.gate.Handle(w, r) {
		return nil
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
//	pay_per_crawl {
//	    pay_to 0x...
//	    price 0.01
//	    mode gate|monitor
//	    facilitator https://facilitator.payai.network
//	    facilitator_auth "Bearer ..."
//	    policy <class> <free|paid|block>
//	    bot <name> <free|paid|block>
//	    allow_path /public/
//	    trusted_ip_header CF-Connecting-IP
//	    pro_key fmppc_...
//	    site_name "My Site"
//	    site_description "..."
//	    contact hello@example.com
//	    realm example.com
//	    mpp_secret {env.PPC_MPP_SECRET}
//	    base_url https://example.com
//	    discovery off
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()         // directive name
	if d.NextArg() { // optional inline pay_to
		h.PayTo = d.Val()
	}
	for d.NextBlock(0) {
		key := d.Val()
		one := func() (string, error) {
			if !d.NextArg() {
				return "", d.ArgErr()
			}
			v := d.Val()
			if d.NextArg() {
				return "", d.ArgErr()
			}
			return v, nil
		}
		two := func() (string, string, error) {
			if !d.NextArg() {
				return "", "", d.ArgErr()
			}
			a := d.Val()
			if !d.NextArg() {
				return "", "", d.ArgErr()
			}
			b := d.Val()
			if d.NextArg() {
				return "", "", d.ArgErr()
			}
			return a, b, nil
		}
		var err error
		switch key {
		case "pay_to":
			h.PayTo, err = one()
		case "price":
			var v string
			if v, err = one(); err == nil {
				if h.PriceUSD, err = strconv.ParseFloat(v, 64); err != nil {
					err = d.Errf("price must be a number of US dollars: %v", err)
				}
			}
		case "mode":
			h.Mode, err = one()
		case "facilitator":
			h.FacilitatorURL, err = one()
		case "facilitator_auth":
			h.FacilitatorAuth, err = one()
		case "policy":
			var c, p string
			if c, p, err = two(); err == nil {
				if h.ClassPolicy == nil {
					h.ClassPolicy = map[string]string{}
				}
				h.ClassPolicy[c] = p
			}
		case "bot":
			var n, p string
			if n, p, err = two(); err == nil {
				if h.BotOverrides == nil {
					h.BotOverrides = map[string]string{}
				}
				h.BotOverrides[n] = p
			}
		case "allow_path":
			var v string
			if v, err = one(); err == nil {
				h.AllowPaths = append(h.AllowPaths, v)
			}
		case "trusted_ip_header":
			h.TrustedIPHeader, err = one()
		case "pro_key":
			h.ProKey, err = one()
		case "site_name":
			h.SiteName, err = one()
		case "site_description":
			h.SiteDescription, err = one()
		case "contact":
			h.Contact, err = one()
		case "realm":
			h.Realm, err = one()
		case "mpp_secret":
			h.MPPSecret, err = one()
		case "base_url":
			h.BaseURL, err = one()
		case "discovery":
			var v string
			if v, err = one(); err == nil {
				switch strings.ToLower(v) {
				case "off", "false", "no":
					h.DisableDiscovery = true
				case "on", "true", "yes":
					h.DisableDiscovery = false
				default:
					err = d.Errf("discovery must be on or off")
				}
			}
		default:
			err = d.Errf("unknown pay_per_crawl option %q", key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards.
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
