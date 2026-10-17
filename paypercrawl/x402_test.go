package paypercrawl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUnits(t *testing.T) {
	if UnitsFromUSD(0.005) != "5000" || UnitsFromUSD(0.01) != "10000" || UnitsFromUSD(1.5) != "1500000" {
		t.Fatal("units conversion")
	}
}

func TestChallengeShapes(t *testing.T) {
	x := testX402(t, "")
	c := x.Challenge("https://example.test/post/", "Example: page", "", "", "")
	if c.Status != 402 {
		t.Fatal(c.Status)
	}
	// PAYMENT-REQUIRED: base64 v2 envelope.
	raw, err := base64.StdEncoding.DecodeString(c.Headers["PAYMENT-REQUIRED"])
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		X402Version int                                         `json:"x402Version"`
		Error       string                                      `json:"error"`
		Resource    struct{ URL, Description, MimeType string } `json:"resource"`
		Accepts     []struct {
			Scheme, Network, Amount, Asset, PayTo string
			MaxTimeoutSeconds                     int
			Extra                                 struct{ Name, Version string }
		} `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	a := env.Accepts[0]
	if env.X402Version != 2 || env.Error != "Payment required" || env.Resource.URL != "https://example.test/post/" || env.Resource.MimeType != "text/html" ||
		a.Scheme != "exact" || a.Network != "eip155:8453" || a.Amount != "10000" || a.Asset != USDC || a.PayTo != testPayTo ||
		a.MaxTimeoutSeconds != 300 || a.Extra.Name != "USD Coin" || a.Extra.Version != "2" {
		t.Fatalf("v2 envelope: %s", raw)
	}
	// JSON body: v1 shape.
	var b map[string]any
	_ = json.Unmarshal(c.Body, &b)
	acc := b["accepts"].([]any)[0].(map[string]any)
	if b["x402Version"].(float64) != 1 || acc["network"] != "base" || acc["maxAmountRequired"] != "10000" || acc["resource"] != "https://example.test/post/" {
		t.Fatalf("v1 body: %s", c.Body)
	}
	if _, has := b["invalidReason"]; has {
		t.Fatal("unpaid challenge must not carry invalidReason")
	}
	if c.Headers["Cache-Control"] != "no-store" || !strings.HasPrefix(c.Headers["WWW-Authenticate"], `Payment id="`) || c.ContentType != "application/json; charset=utf-8" {
		t.Fatalf("headers: %+v", c.Headers)
	}
	// Rejection: invalidReason in body, reason in envelope error.
	c = x.Challenge("u", "d", "insufficient_funds", "", RailV2)
	_ = json.Unmarshal(c.Body, &b)
	if b["invalidReason"] != "insufficient_funds" || b["error"] != "Payment rejected" {
		t.Fatalf("rejection body: %s", c.Body)
	}
	raw, _ = base64.StdEncoding.DecodeString(c.Headers["PAYMENT-REQUIRED"])
	if !strings.Contains(string(raw), `"error":"insufficient_funds"`) {
		t.Fatalf("envelope error: %s", raw)
	}
	// MPP rail rejection: problem+json.
	c = x.Challenge("u", "d", "invalid-challenge", "bad id", RailMPP)
	if c.ContentType != "application/problem+json; charset=utf-8" || !strings.Contains(string(c.Body), MPPProblems+"invalid-challenge") || !strings.Contains(string(c.Body), `"detail":"bad id"`) {
		t.Fatalf("problem: %s %s", c.ContentType, c.Body)
	}
}

func TestMPPChallengeHeader(t *testing.T) {
	x := testX402(t, "")
	h := x.MPPChallenge("Example: page")
	if !strings.HasPrefix(h, `Payment id="`) || !strings.Contains(h, `realm="example.test", method="evm", intent="charge", expires="`) {
		t.Fatal(h)
	}
	i := strings.Index(h, `request="`)
	req := b64URLJSON(strings.TrimSuffix(h[i+9:], `"`))
	md := req["methodDetails"].(map[string]any)
	if req["amount"] != "10000" || md["chainId"].(float64) != 8453 || req["currency"] != USDC || req["recipient"] != testPayTo {
		t.Fatalf("request: %v", req)
	}
	// JCS: keys sorted, no whitespace.
	rawReq, _ := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(h[i+9:], `"`))
	if !strings.HasPrefix(string(rawReq), `{"amount":"10000","currency":"`) || strings.Contains(string(rawReq), " :") {
		t.Fatalf("not canonical: %s", rawReq)
	}
}

func TestMPPRoundTrip(t *testing.T) {
	x := testX402(t, "")
	hdr := mppHeader(t, x.MPPChallenge("d"), nil)
	p := x.ExtractPayment(map[string]string{"authorization": hdr}, "https://example.test/post/")
	if p == nil || p.Rail != RailMPP || p.Error != "" || asInt(p.Payload["x402Version"]) != 2 {
		t.Fatalf("credential rejected: %+v", p)
	}
	if got := p.Authorization()["nonce"]; got != MPPNonce(p.MPP["challenge"].(map[string]any)["id"].(string), "example.test") {
		t.Fatalf("nonce %v", got)
	}
	if e := x.Precheck(p, "u"); e != "" {
		t.Fatal(e)
	}
	bad := func(name string, mut func(map[string]any), want string) {
		t.Helper()
		p := x.ExtractPayment(map[string]string{"authorization": mppHeader(t, x.MPPChallenge("d"), mut)}, "u")
		if p == nil || p.Error != want {
			t.Errorf("%s: got %+v want %s", name, p, want)
		}
	}
	bad("wrong nonce", func(c map[string]any) { c["payload"].(map[string]any)["nonce"] = nonceN('1') }, "verification-failed")
	bad("tampered id", func(c map[string]any) { c["challenge"].(map[string]any)["id"] = "tampered" }, "invalid-challenge")
	bad("wrong realm", func(c map[string]any) { c["challenge"].(map[string]any)["realm"] = "evil.test" }, "invalid-challenge")
	bad("expired", func(c map[string]any) {
		c["challenge"].(map[string]any)["expires"] = time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	}, "payment-expired") // the clock is checked before the HMAC binding, as in the PHP reference
	bad("wrong credential type", func(c map[string]any) { c["payload"].(map[string]any)["type"] = "permit" }, "verification-failed")
	bad("missing field", func(c map[string]any) { delete(c["payload"].(map[string]any), "signature") }, "verification-failed")
	if p := x.ExtractPayment(map[string]string{"authorization": "Bearer abc"}, "u"); p != nil {
		t.Fatal("Bearer must be ignored")
	}
	if p := x.ExtractPayment(map[string]string{"authorization": "Payment !!!"}, "u"); p != nil {
		t.Fatal("non-token Payment credential is not ours")
	}
	if p := x.ExtractPayment(map[string]string{"authorization": "Payment e30"}, "u"); p == nil || p.Error != "malformed-credential" {
		t.Fatalf("empty credential: %+v", p)
	}
}

func TestMPPExpiredChallengeByClock(t *testing.T) {
	x := testX402(t, "")
	hdr := mppHeader(t, x.MPPChallenge("d"), nil)
	later := NewX402(x.p)
	later.p.Now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if p := later.ExtractPayment(map[string]string{"authorization": hdr}, "u"); p == nil || p.Error != "payment-expired" {
		t.Fatalf("%+v", p)
	}
}

func TestExtractAndPrecheck(t *testing.T) {
	x := testX402(t, "")
	p := x.ExtractPayment(map[string]string{"payment-signature": v2Header(x, nonceN('2'))}, "u")
	if p.Rail != RailV2 || x.Precheck(p, "u") != "" {
		t.Fatalf("v2: %+v", p)
	}
	p = x.ExtractPayment(map[string]string{"x-payment": v1Header(nonceN('2'))}, "u")
	if p.Rail != RailV1 || x.Precheck(p, "u") != "" {
		t.Fatalf("v1: %+v", p)
	}
	if e := x.ExtractPayment(map[string]string{"payment-signature": "zzz"}, "u").Error; e != "malformed_payment_signature" {
		t.Fatal(e)
	}
	if e := x.ExtractPayment(map[string]string{"x-payment": enc(map[string]any{"x402Version": 2})}, "u").Error; e != "malformed_x_payment" {
		t.Fatal(e)
	}
	if x.ExtractPayment(map[string]string{}, "u") != nil {
		t.Fatal("no header, no payment")
	}

	mod := func(rail string, f func(auth, top map[string]any)) string {
		a := authz(nonceN('3'))
		top := map[string]any{"x402Version": 2, "accepted": x.RequirementsV2("u"), "payload": map[string]any{"signature": "0xs", "authorization": a}}
		hk := "payment-signature"
		if rail == RailV1 {
			top = map[string]any{"x402Version": 1, "scheme": "exact", "network": "base", "payload": map[string]any{"signature": "0xs", "authorization": a}}
			hk = "x-payment"
		}
		f(a, top)
		pp := x.ExtractPayment(map[string]string{hk: enc(top)}, "u")
		return x.Precheck(pp, "u")
	}
	for _, tc := range []struct {
		name, rail, want string
		f                func(a, top map[string]any)
	}{
		{"wrong payTo", RailV2, "wrong_pay_to", func(a, _ map[string]any) { a["to"] = "0x" + strings.Repeat("c", 40) }},
		{"payTo case-insensitive", RailV2, "", func(a, _ map[string]any) { a["to"] = strings.ToLower(testPayTo) }},
		{"underpay v2", RailV2, "wrong_amount", func(a, _ map[string]any) { a["value"] = "9999" }},
		{"overpay v2", RailV2, "wrong_amount", func(a, _ map[string]any) { a["value"] = "10001" }},
		{"overpay v1 allowed", RailV1, "", func(a, _ map[string]any) { a["value"] = "20000" }},
		{"underpay v1", RailV1, "wrong_amount", func(a, _ map[string]any) { a["value"] = "9999" }},
		{"non-numeric value", RailV2, "wrong_amount", func(a, _ map[string]any) { a["value"] = "ten" }},
		{"expired", RailV2, "authorization_expired", func(a, _ map[string]any) { a["validBefore"] = "1" }},
		{"missing nonce", RailV2, "malformed_authorization", func(a, _ map[string]any) { delete(a, "nonce") }},
		{"v2 wrong network", RailV2, "wrong_network_or_asset", func(_, top map[string]any) { top["accepted"].(Requirement)["network"] = "eip155:1" }},
		{"v2 wrong asset", RailV2, "wrong_network_or_asset", func(_, top map[string]any) { top["accepted"].(Requirement)["asset"] = "0xdead" }},
		{"v1 wrong network", RailV1, "wrong_network_or_scheme", func(_, top map[string]any) { top["network"] = "base-sepolia" }},
	} {
		if got := mod(tc.rail, tc.f); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestFacilitatorFlowV2(t *testing.T) {
	m := newMockFacilitator(t)
	x := testX402(t, m.srv.URL+"/")
	p := x.ExtractPayment(map[string]string{"payment-signature": v2Header(x, nonceN('4'))}, "https://example.test/x")
	s := x.VerifyAndSettle(context.Background(), p, "https://example.test/x")
	if !s.OK || s.Tx != "0xtx1" || s.Payer != "0xpayer" {
		t.Fatalf("%+v", s)
	}
	calls := m.snapshot()
	if len(calls) != 2 || calls[0].Path != "/verify" || calls[1].Path != "/settle" {
		t.Fatalf("order: %+v", calls)
	}
	b := calls[0].Body
	req := b["paymentRequirements"].(map[string]any)
	pp := b["paymentPayload"].(map[string]any)
	if b["x402Version"].(float64) != 2 || req["network"] != "eip155:8453" || req["amount"] != "10000" ||
		pp["accepted"].(map[string]any)["payTo"] != testPayTo || pp["resource"].(map[string]any)["url"] != "https://example.test/x" {
		t.Fatalf("v2 body: %v", b)
	}
}

func TestFacilitatorFlowV1StaysV1(t *testing.T) {
	m := newMockFacilitator(t)
	x := testX402(t, m.srv.URL)
	p := x.ExtractPayment(map[string]string{"x-payment": v1Header(nonceN('5'))}, "https://example.test/x")
	if s := x.VerifyAndSettle(context.Background(), p, "https://example.test/x"); !s.OK {
		t.Fatalf("%+v", s)
	}
	b := m.snapshot()[0].Body
	req := b["paymentRequirements"].(map[string]any)
	pp := b["paymentPayload"].(map[string]any)
	if b["x402Version"].(float64) != 1 || req["network"] != "base" || req["maxAmountRequired"] != "10000" || pp["network"] != "base" {
		t.Fatalf("v1 must be forwarded in v1 shape: %v", b)
	}
	if _, has := pp["accepted"]; has {
		t.Fatal("v1 payload must not gain a v2 'accepted' field")
	}
}

func TestFacilitatorFailures(t *testing.T) {
	m := newMockFacilitator(t)
	x := testX402(t, m.srv.URL)
	p := x.ExtractPayment(map[string]string{"payment-signature": v2Header(x, nonceN('6'))}, "u")

	m.mu.Lock()
	m.settle = map[string]any{"success": true, "transaction": ""}
	m.mu.Unlock()
	if s := x.VerifyAndSettle(context.Background(), p, "u"); s.OK || s.Reason != "settlement_failed" {
		t.Fatalf("empty tx is not a sale: %+v", s)
	}

	m.mu.Lock()
	m.settle = map[string]any{"success": false, "transaction": "0xabc", "errorReason": "insufficient_funds"}
	m.mu.Unlock()
	if s := x.VerifyAndSettle(context.Background(), p, "u"); s.OK || s.Reason != "insufficient_funds" {
		t.Fatalf("success:false with a hash is still not a sale: %+v", s)
	}

	m.mu.Lock()
	m.verify = map[string]any{"isValid": false, "invalidReason": "insufficient_funds", "payer": "0xp"}
	m.mu.Unlock()
	before := len(m.snapshot())
	s := x.VerifyAndSettle(context.Background(), p, "u")
	if s.OK || s.Reason != "insufficient_funds" || s.Payer != "0xp" || len(m.snapshot())-before != 1 {
		t.Fatalf("invalidReason must surface and /settle must not be called: %+v", s)
	}

	m.mu.Lock()
	m.rawVerif = "<html>bad gateway</html>"
	m.mu.Unlock()
	if s := x.VerifyAndSettle(context.Background(), p, "u"); s.Reason != "facilitator_unreachable" || !strings.Contains(s.Detail, "HTTP 502") {
		t.Fatalf("%+v", s)
	}

	dead := testX402(t, "http://127.0.0.1:1")
	if s := dead.VerifyAndSettle(context.Background(), p, "u"); s.Reason != "facilitator_unreachable" {
		t.Fatalf("%+v", s)
	}
}

func TestFacilitatorAuthHeaderAndDefault(t *testing.T) {
	m := newMockFacilitator(t)
	x := NewX402(Params{PayTo: testPayTo, PriceUSD: 0.01, FacilitatorURL: m.srv.URL, FacilitatorAuth: "Bearer k", MPPSecret: "s", Realm: "r"})
	p := x.ExtractPayment(map[string]string{"payment-signature": v2Header(x, nonceN('7'))}, "u")
	x.VerifyAndSettle(context.Background(), p, "u")
	if m.snapshot()[0].Auth != "Bearer k" {
		t.Fatal("auth header not sent")
	}
	if NewX402(Params{}).facilitatorURL() != "https://facilitator.payai.network" {
		t.Fatal("default facilitator")
	}
}

func TestNonceLock(t *testing.T) {
	l := NewMemoryLock()
	now := time.Now()
	l.now = func() time.Time { return now }
	if !l.Acquire("a", time.Minute) || l.Acquire("a", time.Minute) {
		t.Fatal("second acquire must fail")
	}
	l.Release("a")
	if !l.Acquire("a", time.Minute) {
		t.Fatal("released key must be free")
	}
	now = now.Add(2 * time.Minute)
	if !l.Acquire("a", time.Minute) {
		t.Fatal("expired key must be free")
	}
}
