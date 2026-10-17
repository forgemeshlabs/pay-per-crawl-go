package paypercrawl

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Wire constants (Base mainnet USDC).
const (
	NetworkV2          = "eip155:8453"
	NetworkV1          = "base"
	USDC               = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	USDCName           = "USD Coin"
	USDCVersion        = "2"
	USDCDecimals       = 6
	TimeoutSeconds     = 300
	MPPProblems        = "https://paymentauth.org/problems/"
	DefaultFacilitator = "https://facilitator.payai.network"
)

var mppAuthRe = regexp.MustCompile(`(?i)^Payment\s+([A-Za-z0-9_\-]+)$`)

// Rails a payment can arrive on.
const (
	RailV2  = "x402v2"
	RailV1  = "x402v1"
	RailMPP = "mpp"
)

// Params are the per-request inputs the wire layer needs.
type Params struct {
	PayTo           string
	PriceUSD        float64
	FacilitatorURL  string
	FacilitatorAuth string
	MPPSecret       string
	Realm           string
	SiteName        string
	ManifestURL     string
	HTTPClient      HTTPDoer
	Now             func() time.Time
}

// X402 builds challenges and parses/validates payments for one price and recipient.
type X402 struct{ p Params }

// NewX402 returns the wire helper. Params.MPPSecret must be set for MPP to work.
func NewX402(p Params) *X402 {
	if p.Now == nil {
		p.Now = time.Now
	}
	return &X402{p: p}
}

func (x *X402) facilitatorURL() string {
	u := strings.TrimSpace(x.p.FacilitatorURL)
	if u == "" {
		u = DefaultFacilitator
	}
	return strings.TrimRight(u, "/")
}

// UnitsFromUSD converts dollars to USDC micro-units as a decimal string.
func UnitsFromUSD(usd float64) string {
	return strconv.FormatInt(int64(usd*1e6+0.5), 10)
}

// Price is the amount in micro-units.
func (x *X402) Price() string { return UnitsFromUSD(x.p.PriceUSD) }

// Requirement is one entry of accepts[].
type Requirement map[string]any

// RequirementsV2 returns the v2 accepts entry.
func (x *X402) RequirementsV2(resourceURL string) Requirement {
	return Requirement{
		"scheme": "exact", "network": NetworkV2, "amount": x.Price(), "asset": USDC,
		"payTo": x.p.PayTo, "maxTimeoutSeconds": TimeoutSeconds,
		"extra": map[string]any{"name": USDCName, "version": USDCVersion},
	}
}

// RequirementsV1 returns the v1 accepts entry (network "base", maxAmountRequired).
func (x *X402) RequirementsV1(resourceURL, description string) Requirement {
	return Requirement{
		"scheme": "exact", "network": NetworkV1, "maxAmountRequired": x.Price(), "asset": USDC,
		"payTo": x.p.PayTo, "maxTimeoutSeconds": TimeoutSeconds,
		"resource": resourceURL, "description": description, "mimeType": "text/html",
		"extra": map[string]any{"name": USDCName, "version": USDCVersion},
	}
}

// EnvelopeV2 is the object that goes base64 into PAYMENT-REQUIRED.
func (x *X402) EnvelopeV2(resourceURL, description, errMsg string) map[string]any {
	return map[string]any{
		"x402Version": 2, "error": errMsg,
		"resource": map[string]any{"url": resourceURL, "description": description, "mimeType": "text/html"},
		"accepts":  []any{x.RequirementsV2(resourceURL)},
	}
}

// BodyV1 is the JSON body for stock x402-fetch 1.x clients.
func (x *X402) BodyV1(resourceURL, description, errMsg, invalidReason string) map[string]any {
	b := map[string]any{
		"x402Version": 1, "error": errMsg,
		"accepts":  []any{x.RequirementsV1(resourceURL, description)},
		"provider": map[string]any{"name": x.p.SiteName, "plugin": "forgemesh-pay-per-crawl-go"},
		"docs":     map[string]any{"x402": "https://x402.org", "manifest": x.p.ManifestURL},
	}
	if invalidReason != "" {
		b["invalidReason"] = invalidReason
	}
	return b
}

// ChallengeResponse is a ready-to-write 402.
type ChallengeResponse struct {
	Status      int
	Headers     map[string]string
	ContentType string
	Body        []byte // the same JSON a GET gets; callers drop it for HEAD
}

// Challenge builds the 402: PAYMENT-REQUIRED (base64 v2 envelope), WWW-Authenticate: Payment
// (MPP), and a v1-shaped JSON body (or an MPP problem document when the failed attempt was on
// the MPP rail). reason is empty for a first, unpaid request.
func (x *X402) Challenge(resourceURL, description, reason, detail, rail string) *ChallengeResponse {
	errMsg := "Payment required"
	if reason != "" {
		errMsg = reason
	}
	env, _ := marshalNoEscape(x.EnvelopeV2(resourceURL, description, errMsg))
	r := &ChallengeResponse{
		Status: 402,
		Headers: map[string]string{
			"Cache-Control":    "no-store",
			"PAYMENT-REQUIRED": base64.StdEncoding.EncodeToString(env),
			"WWW-Authenticate": x.MPPChallenge(description),
			"Link":             "<" + x.p.ManifestURL + ">; rel=\"describedby\"; type=\"application/json\"",
			"X-Robots-Tag":     "noindex",
		},
	}
	if rail == RailMPP && reason != "" {
		d := detail
		if d == "" {
			d = reason
		}
		r.ContentType = "application/problem+json; charset=utf-8"
		r.Body, _ = marshalNoEscape(map[string]any{"type": MPPProblems + reason, "title": "Payment Required", "status": 402, "detail": d})
		return r
	}
	msg := "Payment required"
	if reason != "" {
		msg = "Payment rejected"
	}
	r.ContentType = "application/json; charset=utf-8"
	r.Body, _ = marshalNoEscape(x.BodyV1(resourceURL, description, msg, reason))
	return r
}

// ── Inbound payments ─────────────────────────────────────────────────────────

// Payment is a parsed inbound payment attempt.
type Payment struct {
	Rail    string         // RailV2, RailV1 or RailMPP
	Payload map[string]any // x402 payment object (v2 structure for v2 and MPP, v1 structure for v1)
	Error   string         // non-empty when the attempt was malformed
	Detail  string
	MPP     map[string]any // parsed MPP credential
}

// ExtractPayment finds a payment on the request. h is a lowercased header map.
// It returns nil when the request carries no payment header.
func (x *X402) ExtractPayment(h map[string]string, resourceURL string) *Payment {
	if v := h["payment-signature"]; v != "" {
		p := b64JSON(v)
		if p == nil || asInt(p["x402Version"]) != 2 || isEmpty(p["payload"]) {
			return &Payment{Rail: RailV2, Error: "malformed_payment_signature"}
		}
		return &Payment{Rail: RailV2, Payload: p}
	}
	if v := h["x-payment"]; v != "" {
		p := b64JSON(v)
		if p == nil || asInt(p["x402Version"]) != 1 || isEmpty(p["payload"]) {
			return &Payment{Rail: RailV1, Error: "malformed_x_payment"}
		}
		return &Payment{Rail: RailV1, Payload: p}
	}
	if m := mppAuthRe.FindStringSubmatch(strings.TrimSpace(h["authorization"])); m != nil {
		cred := b64URLJSON(m[1])
		if perr, detail := x.validateMPP(cred); perr != "" {
			return &Payment{Rail: RailMPP, Error: perr, Detail: detail}
		}
		pl := cred["payload"].(map[string]any)
		v2 := map[string]any{
			"x402Version": 2,
			"resource":    map[string]any{"url": resourceURL},
			"accepted":    x.RequirementsV2(resourceURL),
			"payload": map[string]any{
				"signature": pl["signature"],
				"authorization": map[string]any{
					"from": pl["from"], "to": pl["to"], "value": pl["value"],
					"validAfter": pl["validAfter"], "validBefore": pl["validBefore"], "nonce": pl["nonce"],
				},
			},
		}
		return &Payment{Rail: RailMPP, Payload: v2, MPP: cred}
	}
	return nil
}

// Authorization returns the EIP-3009 authorization inside the payment, or nil.
func (p *Payment) Authorization() map[string]any {
	inner, _ := p.Payload["payload"].(map[string]any)
	a, _ := inner["authorization"].(map[string]any)
	return a
}

// Precheck runs the cheap local checks before talking to the facilitator: right recipient,
// amount, network/asset and expiry. It returns an error code, or "" when the payment passes.
func (x *X402) Precheck(p *Payment, resourceURL string) string {
	auth := p.Authorization()
	if auth == nil || str(auth["to"]) == "" || auth["value"] == nil || str(auth["nonce"]) == "" {
		return "malformed_authorization"
	}
	if !strings.EqualFold(str(auth["to"]), x.p.PayTo) {
		return "wrong_pay_to"
	}
	want, _ := new(big.Int).SetString(x.Price(), 10)
	got, isNum := new(big.Int).SetString(str(auth["value"]), 10)
	// v1 clients may overpay (maxAmountRequired is a ceiling); v2 and MPP must match exactly.
	if !isNum || got.Sign() < 0 || (got.Cmp(want) != 0 && !(got.Cmp(want) > 0 && p.Rail == RailV1)) {
		return "wrong_amount"
	}
	switch p.Rail {
	case RailV2:
		acc, _ := p.Payload["accepted"].(map[string]any)
		if str(acc["network"]) != NetworkV2 || !strings.EqualFold(str(acc["asset"]), USDC) {
			return "wrong_network_or_asset"
		}
	case RailV1:
		if str(p.Payload["network"]) != NetworkV1 || str(p.Payload["scheme"]) != "exact" {
			return "wrong_network_or_scheme"
		}
	}
	if vb, ok := new(big.Int).SetString(str(auth["validBefore"]), 10); ok && vb.Cmp(big.NewInt(x.p.Now().Unix())) < 0 {
		return "authorization_expired"
	}
	return ""
}

// ── MPP ──────────────────────────────────────────────────────────────────────

func (x *X402) challengeID(realm, requestB64, expires, digest, opaque string) string {
	input := strings.Join([]string{realm, "evm", "charge", requestB64, expires, digest, opaque}, "|")
	m := hmac.New(sha256.New, []byte(x.p.MPPSecret))
	m.Write([]byte(input))
	return b64url(m.Sum(nil))
}

// MPPChallenge returns the WWW-Authenticate: Payment header value.
func (x *X402) MPPChallenge(description string) string {
	req := map[string]any{
		"amount": x.Price(), "currency": USDC, "recipient": x.p.PayTo,
		"methodDetails": map[string]any{"chainId": 8453, "credentialTypes": []any{"authorization"}, "decimals": USDCDecimals},
	}
	if description != "" {
		req["description"] = description
	}
	// encoding/json emits object keys sorted, which is RFC 8785 order for these value shapes.
	raw, _ := marshalNoEscape(req)
	reqB64 := b64url(raw)
	expires := x.p.Now().UTC().Add(TimeoutSeconds * time.Second).Format("2006-01-02T15:04:05Z")
	id := x.challengeID(x.p.Realm, reqB64, expires, "", "")
	return fmt.Sprintf(`Payment id="%s", realm="%s", method="evm", intent="charge", expires="%s", request="%s"`, id, x.p.Realm, expires, reqB64)
}

// MPPNonce is the EIP-3009 nonce an MPP credential must carry: keccak256(id || realm).
func MPPNonce(id, realm string) string { return Keccak256Hex([]byte(id + realm)) }

func (x *X402) validateMPP(cred map[string]any) (problem, detail string) {
	ch, _ := cred["challenge"].(map[string]any)
	pl, _ := cred["payload"].(map[string]any)
	if cred == nil || len(ch) == 0 || len(pl) == 0 {
		return "malformed-credential", "Credential must contain challenge and payload objects."
	}
	if str(ch["realm"]) != x.p.Realm || str(ch["method"]) != "evm" || str(ch["intent"]) != "charge" ||
		str(ch["id"]) == "" || str(ch["request"]) == "" || str(ch["expires"]) == "" {
		return "invalid-challenge", "Challenge fields missing or not issued by this realm."
	}
	exp, err := time.Parse(time.RFC3339, str(ch["expires"]))
	if err != nil || exp.Before(x.p.Now()) {
		return "payment-expired", "Challenge has expired; retry with a fresh challenge."
	}
	want := x.challengeID(str(ch["realm"]), str(ch["request"]), str(ch["expires"]), str(ch["digest"]), str(ch["opaque"]))
	if !hmac.Equal([]byte(want), []byte(str(ch["id"]))) {
		return "invalid-challenge", "Challenge id does not match its parameters."
	}
	req := b64URLJSON(str(ch["request"]))
	if req == nil || str(req["amount"]) != x.Price() || !strings.EqualFold(str(req["recipient"]), x.p.PayTo) || !strings.EqualFold(str(req["currency"]), USDC) {
		return "invalid-challenge", "Challenge request does not match this resource's payment terms."
	}
	if str(pl["type"]) != "authorization" {
		return "verification-failed", `Only credentialTypes ["authorization"] (EIP-3009) is accepted.`
	}
	for _, f := range []string{"from", "to", "value", "validAfter", "validBefore", "nonce", "signature"} {
		if s, ok := pl[f].(string); !ok || s == "" {
			return "verification-failed", "Payload field " + f + " is required."
		}
	}
	if !strings.EqualFold(str(pl["nonce"]), MPPNonce(str(ch["id"]), str(ch["realm"]))) {
		return "verification-failed", "Payload nonce must equal keccak256(challenge.id || challenge.realm)."
	}
	return "", ""
}

// MPPReceipt is the Payment-Receipt header value for a settled MPP payment.
func (x *X402) MPPReceipt(tx string) string {
	raw, _ := marshalNoEscape(map[string]any{"status": "success", "method": "evm", "timestamp": x.p.Now().UTC().Format("2006-01-02T15:04:05Z"), "reference": tx})
	return b64url(raw)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64JSON(s string) map[string]any {
	d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		d, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return nil
		}
	}
	var m map[string]any
	if json.Unmarshal(d, &m) != nil {
		return nil
	}
	return m
}

func b64URLJSON(s string) map[string]any {
	d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(d, &m) != nil {
		return nil
	}
	return m
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	}
	return 0
}

func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}
