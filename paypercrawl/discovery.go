package paypercrawl

import (
	"strconv"
	"strings"
)

// Discovery paths served by the Gate (and exempt from gating).
var discoveryPaths = []string{"/.well-known/x402.json", "/llms.txt", "/agents.txt"}

func trimPrice(p float64) string {
	s := strings.TrimRight(strings.TrimRight(formatFixed6(p), "0"), ".")
	if s == "" {
		return "0"
	}
	return s
}

func formatFixed6(p float64) string { return strconv.FormatFloat(p, 'f', 6, 64) }

func (g *Gate) paid() bool { return g.cfg.mode() == ModeGate && g.cfg.PayTo != "" }

func (g *Gate) siteName(host string) string {
	if g.cfg.SiteName != "" {
		return g.cfg.SiteName
	}
	return host
}

// Manifest is /.well-known/x402.json for the site at base (scheme://host).
func (g *Gate) Manifest(base, host string) map[string]any {
	price := g.cfg.price()
	res := map[string]any{
		"resource": base + "/{path}",
		"type":     "http",
		"metadata": map[string]any{
			"method":      "GET",
			"name":        g.siteName(host) + ": page fetch",
			"description": "Any page on " + host + ", served to automated clients after an x402 payment of $" + trimPrice(price) + " USDC on Base. Humans and verified search engines read free.",
			"priceUsd":    price,
			"mimeType":    "text/html",
			"paid":        g.paid(),
		},
		"accepts": []any{map[string]any{
			"scheme": "exact", "network": NetworkV2, "amount": UnitsFromUSD(price), "asset": USDC,
			"payTo": g.cfg.PayTo, "maxTimeoutSeconds": TimeoutSeconds,
			"extra": map[string]any{"name": USDCName, "version": USDCVersion},
		}},
	}
	provider := map[string]any{"name": g.siteName(host), "url": base + "/", "description": g.cfg.SiteDescription}
	if g.cfg.Contact != "" {
		provider["contact"] = g.cfg.Contact
	} else {
		provider["contact"] = nil
	}
	return map[string]any{
		"x402Version": 2,
		"provider":    provider,
		"resources":   []any{res},
		"protocols":   []any{"x402", "mpp"},
		"generator":   "forgemesh-pay-per-crawl-go/" + Version,
		"sitemap":     base + "/sitemap.xml",
	}
}

// LLMS is /llms.txt.
func (g *Gate) LLMS(base, host string) string {
	l := []string{"# " + g.siteName(host), ""}
	if g.cfg.SiteDescription != "" {
		l = append(l, "> "+g.cfg.SiteDescription, "")
	}
	l = append(l, "Site: "+base+"/", "Sitemap: "+base+"/sitemap.xml", "", "## Access for automated clients", "")
	if g.paid() {
		l = append(l, "Pages on this site answer HTTP 402 to crawlers and agents. Pay $"+trimPrice(g.cfg.price())+" USDC on Base per page with x402 (PAYMENT-SIGNATURE or X-PAYMENT header) or MPP (Authorization: Payment) and retry the same URL.")
	} else {
		l = append(l, "This site is instrumented for x402 pay-per-crawl; charging is not enabled yet. Terms will appear in the manifest below when it is.")
	}
	l = append(l, "Verified search engines and humans are never charged.", "",
		"Manifest: "+base+"/.well-known/x402.json", "Agents: "+base+"/agents.txt", "Protocol: https://x402.org")
	return strings.Join(l, "\n") + "\n"
}

// Agents is /agents.txt.
func (g *Gate) Agents(base, host string) string {
	pay := "none"
	if g.paid() {
		pay = "required"
	}
	l := []string{
		"# agents.txt - " + host,
		"# Standard: https://agents-txt.com",
		"",
		"Name: " + g.siteName(host),
		"Provider: " + g.siteName(host) + " (" + base + "/)",
		"Protocols: x402, mpp, http",
		"Payments: " + pay,
		"",
		"LLMs: " + base + "/llms.txt",
		"x402: " + base + "/.well-known/x402.json",
		"Sitemap: " + base + "/sitemap.xml",
		"",
		"## Payment",
		"Protocol: x402 (HTTP 402 challenge; pay and retry with PAYMENT-SIGNATURE) and MPP (WWW-Authenticate: Payment)",
		"Network: " + NetworkV2,
		"Asset: " + USDC + " (USDC)",
		"Price: $" + trimPrice(g.cfg.price()) + " per page",
		"PayTo: " + g.cfg.PayTo,
		"",
	}
	return strings.Join(l, "\n")
}

// RobotsAppend returns comment lines pointing crawlers at the discovery files. Append them to
// the robots.txt your site already serves.
func (g *Gate) RobotsAppend(base string) string {
	return "\n# x402 pay-per-crawl (pay-per-crawl-go)\n# Manifest: " + base + "/.well-known/x402.json\n# LLMs: " + base + "/llms.txt\n# Agents: " + base + "/agents.txt\n"
}
