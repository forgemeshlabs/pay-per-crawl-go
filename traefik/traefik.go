// Package traefik is the Traefik plugin (Yaegi) adapter for ForgeMesh Pay-per-Crawl.
//
// It uses only the standard library plus this module's own core package, so it loads in
// Traefik's interpreter without vendoring or cgo.
package traefik

import (
	"context"
	"net/http"

	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

// Config is the plugin configuration (the middleware's `plugin.<name>` block).
type Config struct {
	PayTo            string            `json:"payTo,omitempty"`
	PriceUSD         float64           `json:"priceUSD,omitempty"`
	Mode             string            `json:"mode,omitempty"`
	FacilitatorURL   string            `json:"facilitatorURL,omitempty"`
	FacilitatorAuth  string            `json:"facilitatorAuth,omitempty"`
	ClassPolicy      map[string]string `json:"classPolicy,omitempty"`
	BotOverrides     map[string]string `json:"botOverrides,omitempty"`
	AllowPaths       []string          `json:"allowPaths,omitempty"`
	TrustedIPHeader  string            `json:"trustedIPHeader,omitempty"`
	ProKey           string            `json:"proKey,omitempty"`
	SiteName         string            `json:"siteName,omitempty"`
	SiteDescription  string            `json:"siteDescription,omitempty"`
	Contact          string            `json:"contact,omitempty"`
	Realm            string            `json:"realm,omitempty"`
	MPPSecret        string            `json:"mppSecret,omitempty"`
	BaseURL          string            `json:"baseURL,omitempty"`
	DisableDiscovery bool              `json:"disableDiscovery,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{PriceUSD: 0.01, Mode: paypercrawl.ModeGate}
}

// New creates the middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	g, err := paypercrawl.NewGate(paypercrawl.Config{
		PayTo:            config.PayTo,
		PriceUSD:         config.PriceUSD,
		Mode:             config.Mode,
		FacilitatorURL:   config.FacilitatorURL,
		FacilitatorAuth:  config.FacilitatorAuth,
		ClassPolicy:      config.ClassPolicy,
		BotOverrides:     config.BotOverrides,
		AllowPaths:       config.AllowPaths,
		TrustedIPHeader:  config.TrustedIPHeader,
		ProKey:           config.ProKey,
		SiteName:         config.SiteName,
		SiteDescription:  config.SiteDescription,
		Contact:          config.Contact,
		Realm:            config.Realm,
		MPPSecret:        config.MPPSecret,
		BaseURL:          config.BaseURL,
		DisableDiscovery: config.DisableDiscovery,
	})
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		g.Close()
	}()
	return g.Middleware(next), nil
}
