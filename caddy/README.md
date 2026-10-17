# Caddy module `http.handlers.pay_per_crawl`

## Install

```
xcaddy build --with github.com/forgemeshlabs/pay-per-crawl-go/caddy
```

## Caddyfile

```
example.com {
	pay_per_crawl {
		pay_to {env.PAY_TO}
		price 0.01
		mode gate                 # or monitor
		policy ai paid            # class policy: free | paid | block
		bot Bytespider block      # per-bot override
		allow_path /public/
		# trusted_ip_header CF-Connecting-IP
		# mpp_secret {env.PPC_MPP_SECRET}
	}
	reverse_proxy localhost:8080
}
```

The directive is ordered before `header`, so it runs ahead of `reverse_proxy`, `respond` and
`file_server` wherever you write it. Other options: `facilitator`, `facilitator_auth`, `site_name`,
`site_description`, `contact`, `realm`, `base_url`, `discovery off`, `pro_key`. Values accept Caddy
placeholders such as `{env.PAY_TO}`. Full example: [`examples/caddy/Caddyfile`](../examples/caddy/Caddyfile).

JSON: `{"handler": "pay_per_crawl", "pay_to": "0x...", "price_usd": 0.01}`.

The client IP comes from Caddy's own resolution (`trusted_proxies`), so set that in the global
options when behind a CDN instead of `trusted_ip_header`.

Money flow: the site owner keeps 100%; USDC goes straight to `pay_to`, no custody, account or key.
Behind Cloudflare, "Block AI bots" must be set to Allow. The module requires Caddy v2.8.4 or
newer (xcaddy builds with the latest).
