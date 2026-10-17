// Example: put the pay-per-crawl gate in front of a plain net/http site.
//
//	PAY_TO=0xYourWallet go run ./examples/nethttp
//
// Environment: PAY_TO (required), PORT (default 8080), PRICE_USD (default 0.01),
// MODE (gate|monitor), FACILITATOR_URL (default PayAI, no key needed).
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/forgemeshlabs/pay-per-crawl-go/middleware"
	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

func main() {
	price := 0.01
	if v := os.Getenv("PRICE_USD"); v != "" {
		p, err := strconv.ParseFloat(v, 64)
		if err != nil {
			log.Fatalf("PRICE_USD: %v", err)
		}
		price = p
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>Paid page</title><h1>ZZPAIDZZ</h1><p>You paid for this page.</p>")
	})

	h, err := middleware.New(paypercrawl.Config{
		PayTo:          os.Getenv("PAY_TO"),
		PriceUSD:       price,
		Mode:           os.Getenv("MODE"),
		FacilitatorURL: os.Getenv("FACILITATOR_URL"),
		SiteName:       "Pay-per-Crawl example",
		AllowPaths:     []string{"/free/"},
		OnHit: func(h paypercrawl.Hit) {
			log.Printf("%-13s %-10s %-20s %s tx=%s", h.Status, h.Class, h.BotName, h.Path, h.Tx)
		},
	}, mux)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on :%s (price $%v)", port, price)
	log.Fatal(http.ListenAndServe(":"+port, h))
}
