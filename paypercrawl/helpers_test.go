package paypercrawl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPayTo = "0x13C3C28c64cc9d60eEb8a675F3fe27eBC6a4Cd09"

// mockFacilitator records calls and answers /verify and /settle from fields the test can change.
type mockFacilitator struct {
	mu       sync.Mutex
	srv      *httptest.Server
	calls    []mockCall
	verify   map[string]any
	settle   map[string]any
	rawVerif string
}

type mockCall struct {
	Path string
	Auth string
	Body map[string]any
}

func newMockFacilitator(t *testing.T) *mockFacilitator {
	m := &mockFacilitator{
		verify: map[string]any{"isValid": true, "payer": "0xpayer"},
		settle: map[string]any{"success": true, "transaction": "0xtx1", "network": "eip155:8453", "payer": "0xpayer"},
	}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		m.mu.Lock()
		m.calls = append(m.calls, mockCall{r.URL.Path, r.Header.Get("Authorization"), body})
		v, s, raw := m.verify, m.settle, m.rawVerif
		m.mu.Unlock()
		if raw != "" {
			w.WriteHeader(502)
			_, _ = w.Write([]byte(raw))
			return
		}
		switch r.URL.Path {
		case "/verify":
			_ = json.NewEncoder(w).Encode(v)
		case "/settle":
			_ = json.NewEncoder(w).Encode(s)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockFacilitator) snapshot() []mockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mockCall{}, m.calls...)
}

func testX402(t *testing.T, facURL string) *X402 {
	return NewX402(Params{PayTo: testPayTo, PriceUSD: 0.01, FacilitatorURL: facURL, MPPSecret: "unit-secret",
		Realm: "example.test", SiteName: "Example", ManifestURL: "https://example.test/.well-known/x402.json"})
}

func authz(nonce string) map[string]any {
	return map[string]any{"from": "0x" + strings.Repeat("b", 40), "to": testPayTo, "value": "10000",
		"validAfter": "0", "validBefore": itoa(time.Now().Unix() + 100), "nonce": nonce}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func nonceN(c byte) string { return "0x" + strings.Repeat(string(c), 64) }

func enc(v any) string { b, _ := json.Marshal(v); return base64.StdEncoding.EncodeToString(b) }

func v2Header(x *X402, nonce string) string {
	return enc(map[string]any{"x402Version": 2, "accepted": x.RequirementsV2("u"),
		"payload": map[string]any{"signature": "0xs", "authorization": authz(nonce)}})
}

func v1Header(nonce string) string {
	return enc(map[string]any{"x402Version": 1, "scheme": "exact", "network": "base",
		"payload": map[string]any{"signature": "0xs", "authorization": authz(nonce)}})
}

// mppHeader runs a full MPP round trip: take the challenge the server would issue and answer it.
func mppHeader(t *testing.T, challenge string, mutate func(cred map[string]any)) string {
	t.Helper()
	kv := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(challenge, "Payment "), ", ") {
		i := strings.Index(part, "=")
		kv[part[:i]] = strings.Trim(part[i+1:], `"`)
	}
	cred := map[string]any{
		"challenge": map[string]any{"id": kv["id"], "realm": kv["realm"], "method": kv["method"], "intent": kv["intent"], "expires": kv["expires"], "request": kv["request"]},
		"payload": map[string]any{"type": "authorization", "from": "0x" + strings.Repeat("a", 40), "to": testPayTo, "value": "10000",
			"validAfter": "0", "validBefore": itoa(time.Now().Unix() + 300), "nonce": MPPNonce(kv["id"], kv["realm"]), "signature": "0xsig"},
	}
	if mutate != nil {
		mutate(cred)
	}
	raw, _ := json.Marshal(cred)
	return "Payment " + base64.RawURLEncoding.EncodeToString(raw)
}

type fakeResolver struct {
	ptr map[string][]string
	fwd map[string][]string
	err error
}

func (f fakeResolver) LookupAddr(ctx context.Context, a string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if n, ok := f.ptr[a]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: a, IsNotFound: true}
}

func (f fakeResolver) LookupHost(ctx context.Context, h string) ([]string, error) {
	if a, ok := f.fwd[h]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}
