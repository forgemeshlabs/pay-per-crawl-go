package paypercrawl

import "net/http"

// NewHandler wraps next with the gate. Requests the gate answers itself (402, 403, discovery
// documents) never reach next.
func NewHandler(cfg Config, next http.Handler) (http.Handler, error) {
	g, err := NewGate(cfg)
	if err != nil {
		return nil, err
	}
	return g.Middleware(next), nil
}

// Handler is NewHandler that panics on an invalid Config (like regexp.MustCompile), for use in main().
func Handler(cfg Config, next http.Handler) http.Handler {
	h, err := NewHandler(cfg, next)
	if err != nil {
		panic(err)
	}
	return h
}

// Middleware returns the gate as a handler wrapper.
func (g *Gate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Handle(w, r) {
			next.ServeHTTP(w, r)
		}
	})
}
