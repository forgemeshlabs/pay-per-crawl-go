// Package middleware is the plain net/http adapter for ForgeMesh Pay-per-Crawl.
//
//	mux := http.NewServeMux()
//	mux.Handle("/", site)
//	http.ListenAndServe(":8080", middleware.Handler(paypercrawl.Config{PayTo: "0x..."}, mux))
package middleware

import (
	"net/http"

	"github.com/forgemeshlabs/pay-per-crawl-go/paypercrawl"
)

// Handler wraps next with the pay-per-crawl gate. It panics on an invalid Config; use New to get the error.
func Handler(cfg paypercrawl.Config, next http.Handler) http.Handler {
	return paypercrawl.Handler(cfg, next)
}

// New is Handler returning the configuration error instead of panicking.
func New(cfg paypercrawl.Config, next http.Handler) (http.Handler, error) {
	return paypercrawl.NewHandler(cfg, next)
}

// Wrap returns the gate as a func(http.Handler) http.Handler for router chains (chi, alice, ...).
func Wrap(cfg paypercrawl.Config) (func(http.Handler) http.Handler, error) {
	g, err := paypercrawl.NewGate(cfg)
	if err != nil {
		return nil, err
	}
	return g.Middleware, nil
}
