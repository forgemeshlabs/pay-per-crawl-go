package paypercrawl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPDoer is the slice of *http.Client used for facilitator and Pro calls.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Settlement is the outcome of VerifyAndSettle.
type Settlement struct {
	OK     bool
	Reason string // failure code: invalidReason from /verify, errorReason from /settle, facilitator_unreachable, ...
	Detail string // transport detail for facilitator_unreachable
	Tx     string // transaction hash, non-empty when OK
	Payer  string
	Raw    map[string]any // the facilitator's /settle body (becomes PAYMENT-RESPONSE)
}

// VerifyAndSettle POSTs /verify then /settle to the facilitator with
// {x402Version, paymentPayload, paymentRequirements}. A v1 payment is forwarded in v1 shape
// (network "base", maxAmountRequired), never translated. The sale only counts when /settle
// returns success with a non-empty transaction hash.
func (x *X402) VerifyAndSettle(ctx context.Context, p *Payment, resourceURL string) Settlement {
	var req Requirement
	version := 2
	pp := map[string]any{}
	for k, v := range p.Payload {
		pp[k] = v
	}
	if p.Rail == RailV1 {
		req = x.RequirementsV1(resourceURL, x.p.SiteName)
		version = 1
	} else {
		req = x.RequirementsV2(resourceURL)
		// The facilitator deep-compares `accepted` with the requirements for v2: send ours.
		pp["accepted"] = req
		if isEmpty(pp["resource"]) {
			pp["resource"] = map[string]any{"url": resourceURL}
		}
	}
	body := map[string]any{"x402Version": version, "paymentPayload": pp, "paymentRequirements": req}

	v, err := x.post(ctx, "/verify", body)
	if err != nil {
		return Settlement{Reason: "facilitator_unreachable", Detail: err.Error()}
	}
	if ok, _ := v["isValid"].(bool); !ok {
		reason := str(v["invalidReason"])
		if reason == "" {
			reason = "verification_failed"
		}
		return Settlement{Reason: reason, Payer: str(v["payer"])}
	}
	s, err := x.post(ctx, "/settle", body)
	if err != nil {
		return Settlement{Reason: "facilitator_unreachable", Detail: err.Error()}
	}
	tx := str(s["transaction"])
	if ok, _ := s["success"].(bool); !ok || tx == "" {
		reason := str(s["errorReason"])
		if reason == "" {
			reason = "settlement_failed"
		}
		return Settlement{Reason: reason, Raw: s}
	}
	payer := str(s["payer"])
	if payer == "" {
		payer = str(v["payer"])
	}
	return Settlement{OK: true, Tx: tx, Payer: payer, Raw: s}
}

func (x *X402) post(ctx context.Context, path string, body map[string]any) (map[string]any, error) {
	raw, err := marshalNoEscape(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.facilitatorURL()+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "forgemesh-pay-per-crawl-go/"+Version)
	if x.p.FacilitatorAuth != "" {
		req.Header.Set("Authorization", x.p.FacilitatorAuth)
	}
	client := x.p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if json.Unmarshal(b, &out) != nil || out == nil {
		snippet := strings.TrimSpace(string(b))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return out, nil
}
