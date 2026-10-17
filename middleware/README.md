# net/http middleware

```
go get github.com/forgemeshlabs/pay-per-crawl-go@v0.1.0
```

```go
h, err := middleware.New(paypercrawl.Config{PayTo: "0xYourWallet", PriceUSD: 0.01}, next)
// or middleware.Handler(cfg, next), which panics on a bad config
// or mw, err := middleware.Wrap(cfg) for chi/alice chains: r.Use(mw)
```

Runnable example: [`examples/nethttp`](../examples/nethttp/main.go)
(`PAY_TO=0x... PORT=8080 go run ./examples/nethttp`).

Money flow: the site owner keeps 100%; USDC goes from the agent to your `PayTo` address through
the facilitator, with no custody, account or key. If you sit behind Cloudflare, "Block AI bots"
must be set to Allow or bots never reach the gate. See the [main README](../README.md) for all
config fields, including how to set `TrustedIPHeader` safely.
