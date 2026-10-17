# ForgeMesh Pay-per-Crawl (Go)

Charge AI crawlers and bots per page. Humans and rDNS-verified search engines read free; AI,
SEO, automation and unknown bots get an HTTP 402 and pay in USDC on Base with
[x402](https://x402.org) (v1 and v2) or MPP, then retry the same URL.

One Go module, one policy engine, three adapters:

| Adapter | Path | Use it for |
|---|---|---|
| net/http middleware | [`middleware`](middleware/README.md) | any Go service |
| Caddy module `http.handlers.pay_per_crawl` | [`caddy`](caddy/README.md) | sites behind Caddy |
| Traefik plugin | [`traefik`](traefik/README.md) | sites behind Traefik |

The core is `paypercrawl` (`Classify`, `Challenge`, `ExtractPayment`, `Precheck`,
`VerifyAndSettle`, `NonceLock`, discovery documents, `Config`). It is a port of the
[WordPress plugin](https://github.com/forgemeshlabs/forgemesh-pay-per-crawl) and behaves the same.

## Money flow

The site owner keeps 100%. The USDC goes from the paying agent's wallet straight to your `PayTo`
address. There is no custody, no ForgeMesh account, no API key and no revenue share. The gate
calls the payment facilitator itself (default `https://facilitator.payai.network`: x402 v1 and
v2, Base mainnet, no key, no seller fee) and serves the page only after `/settle` returns a
non-empty transaction hash. Nothing is sent anywhere else unless you set an optional Pro key.

## Quick start (net/http)

```go
package main

import (
	"net/http"

	"github.com/forgemeshlabs/pay-per-crawl-go/middleware"
	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

func main() {
	site := http.FileServer(http.Dir("./public"))
	http.ListenAndServe(":8080", middleware.Handler(paypercrawl.Config{
		PayTo:    "0xYourWalletAddress",
		PriceUSD: 0.01,
	}, site))
}
```

```
go get github.com/forgemeshlabs/pay-per-crawl-go@v0.1.0
```

## Behaviour

- **Classes:** human, search, social, monitor (free by default); seo, ai, automation, bot (paid).
  85 known crawlers (GPTBot, ClaudeBot, PerplexityBot, AhrefsBot, curl, ...) plus generic bot detection.
- **Search engines are verified** by reverse and forward DNS. A request claiming to be Googlebot
  from a non-Google address is classed `automation` and charged. Without a verifiable IP, or when
  DNS is down, the claim is kept.
- **Policy:** `ClassPolicy` per class and `BotOverrides` per bot, each `free`, `paid` or `block`.
  `Mode: "monitor"` classifies and logs what you would have earned without ever answering 402.
- **402 response:** `PAYMENT-REQUIRED` header (base64 x402 v2 envelope), a v1-shaped JSON body
  (so stock `x402-fetch` 1.x can pay; includes `invalidReason` on a rejected payment), and
  `WWW-Authenticate: Payment` (MPP). HEAD is treated like GET.
- **Payment in:** `PAYMENT-SIGNATURE` (v2), `X-PAYMENT` (v1), `Authorization: Payment` (MPP). Cheap
  local checks first (recipient, amount, asset, network, expiry), then the facilitator `/verify` and
  `/settle`. A v1 payment is forwarded in v1 shape. Receipts: `PAYMENT-RESPONSE` and
  `X-PAYMENT-RESPONSE` (plus `Payment-Receipt` for MPP).
- **Replay lock:** an authorization nonce can be presented once. In-memory by default; implement
  `paypercrawl.NonceLock` over Redis or a database to share it across instances.
- **Discovery:** `/.well-known/x402.json`, `/llms.txt`, `/agents.txt` served for you
  (`DisableDiscovery` turns them off); `Gate.RobotsAppend` returns pointer lines for your robots.txt.
- **Never gated:** `/robots.txt`, `/llms.txt`, `/agents.txt`, `/.well-known/`, `/favicon.ico`,
  `/sitemap*`, and your `AllowPaths`.

## Config

| Field | Default | Notes |
|---|---|---|
| `PayTo` | required in gate mode | `0x` EVM address on Base that receives the USDC |
| `PriceUSD` | `0.01` | per page fetch |
| `Mode` | `gate` | `gate` or `monitor` |
| `FacilitatorURL` | PayAI | any x402 facilitator that supports `exact` on Base |
| `FacilitatorAuth` | none | sent as the `Authorization` header to the facilitator |
| `ClassPolicy`, `BotOverrides` | see Behaviour | `free` / `paid` / `block` |
| `AllowPaths` | none | path prefixes never gated |
| `TrustedIPHeader` | none | see below |
| `ProKey` | none | optional hosted dashboard license (`fmppc_...`) |
| `MPPSecret` | random per process | set a long random string so MPP challenges survive restarts and span instances |
| `BaseURL`, `Realm`, `SiteName`, `SiteDescription`, `Contact` | derived | challenge and discovery text |
| `HTTPClient`, `Lock`, `Resolver`, `OnHit`, `ClientIP` | defaults | injection points |

### Real client IP behind a proxy

Search-engine verification needs the real client address. Set `TrustedIPHeader` only to a header
that **your own proxy overwrites or appends to**. For a multi-value header such as
`X-Forwarded-For` the **right-most** entry is used (the one your proxy added); the left-most is
client-controlled, so a scraper cannot prepend a Googlebot address to get the free lane.
Single-value edge headers (`CF-Connecting-IP`, `X-Real-IP`, `True-Client-IP`) are taken as-is. If the
header is not controlled by your proxy, leave it unset.

### Cloudflare

If the site is behind Cloudflare, **"Block AI bots" / "AI Crawl Control" must be set to Allow** for
the crawlers you want to charge. Cloudflare blocks them at the edge before they ever reach this
gate, so no 402 is served and nothing can be paid. Also set `TrustedIPHeader: "CF-Connecting-IP"`.

## Optional Pro reporter

With a `ProKey` the gate pushes daily rollups and settlements to the hosted dashboard at
`proxy.forgemesh.io` (Bearer auth, hourly) and pulls the crawler-intel feed. Without a key nothing
calls out except the facilitator.

## Verified on mainnet

Real paid calls through the PayAI facilitator against `examples/nethttp`, $0.01 each, to the
payTo wallet; receipts confirmed on Base mainnet (status 0x1, USDC transfer of 10000 units):

| Rail | Transaction |
|---|---|
| x402 v1 (`X-PAYMENT`, network `base`) | `0x948aa9522f9feed31a1a8bc77e7c1de88699b1e629759f5677bd6a2e3117c4e8` |
| x402 v2 (`PAYMENT-SIGNATURE`, `eip155:8453`) | `0x80b5b56043bba8b4b17c95eb9759415affbf9857f8a22a249b841ac16260aebc` |

The Caddy module was built with xcaddy and the Traefik plugin loaded by Traefik v3.7.15 in local
plugin mode; both served the 402, the free human path, HEAD 402, discovery files and a paid retry.

## Development

```
go test -race ./...
```

Keccak-256 (for the MPP nonce) is implemented in pure Go so the core loads inside Traefik's Yaegi
interpreter; tests cross-check it against `golang.org/x/crypto/sha3`.

MIT licensed. ForgeMesh Labs, hello@forgemesh.io.
