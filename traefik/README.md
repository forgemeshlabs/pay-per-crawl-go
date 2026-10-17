# Traefik plugin

Written for Traefik's Yaegi interpreter: standard library plus this module's core package only,
no cgo, no vendoring. Tested against Traefik v3.7.15 in local plugin mode.

## Install

Static configuration:

```yaml
experimental:
  plugins:
    pay-per-crawl:
      moduleName: github.com/forgemeshlabs/pay-per-crawl-go
      version: v0.1.0
```

Dynamic configuration: see [`dynamic.example.yml`](dynamic.example.yml).

```yaml
http:
  middlewares:
    pay-per-crawl:
      plugin:
        pay-per-crawl:
          payTo: "0xYourWalletAddress"
          priceUSD: 0.01
          mode: gate
          allowPaths: ["/public/"]
          botOverrides:
            Bytespider: block
```

Options: `payTo`, `priceUSD`, `mode`, `facilitatorURL`, `facilitatorAuth`, `classPolicy`,
`botOverrides`, `allowPaths`, `trustedIPHeader`, `proKey`, `siteName`, `siteDescription`,
`contact`, `realm`, `mppSecret`, `baseURL`, `disableDiscovery`.

Set `mppSecret` to a long random string so MPP challenges survive restarts. The replay lock is
in-memory per instance. Set `trustedIPHeader` only to a header your edge overwrites or appends to
(right-most entry used for `X-Forwarded-For`).

Money flow: the site owner keeps 100%; USDC goes straight to `payTo`, no custody, account or key.
Behind Cloudflare, "Block AI bots" must be set to Allow.
