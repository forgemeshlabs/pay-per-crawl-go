package paypercrawl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

// DefaultProBase is the hosted dashboard. Nothing is sent without a ProKey.
const DefaultProBase = "https://proxy.forgemesh.io"

var proKeyRe = regexp.MustCompile(`^fmppc_[A-Za-z0-9_\-]{20,}$`)

// ProEnabled reports whether key has the shape of a Pro license key.
func ProEnabled(key string) bool { return proKeyRe.MatchString(key) }

// Hit is one classified request outcome. Status is one of passed, blocked, monitor, unpaid,
// rejected, settle_failed, paid.
type Hit struct {
	Time        time.Time
	Class       string
	BotName     string
	Verified    Verified
	Method      string
	Path        string
	IPHash      string
	UA          string
	Status      string
	Reason      string
	Rail        string
	AmountUnits int64
	Tx          string
	Payer       string
}

type rollKey struct{ day, bot, class string }

type rollVal struct {
	hits, paid, unpaid, rejected, monitor, revenue, would int64
	sources                                               map[string]struct{}
}

type settlementRow struct {
	TS          string `json:"ts"`
	BotName     string `json:"bot_name"`
	UAClass     string `json:"ua_class"`
	Path        string `json:"path"`
	Rail        string `json:"rail"`
	AmountUnits int64  `json:"amount_units"`
	TxHash      string `json:"tx_hash"`
	Payer       string `json:"payer"`
}

// Reporter is the optional Pro reporter: it keeps daily rollups and settlements in memory and
// pushes them to the hosted dashboard with Bearer auth, and pulls the crawler-intel feed.
type Reporter struct {
	key    string
	base   string
	client HTTPDoer
	cls    *Classifier
	now    func() time.Time
	salt   string

	mu          sync.Mutex
	rolls       map[rollKey]*rollVal
	settlements []settlementRow
	host, name  string
	mode        string
	priceUSD    float64
	payTo       string
	verifiedAt  time.Time
	licenseOK   bool
	intelAt     time.Time
}

func newReporter(cfg *Config, cls *Classifier) *Reporter {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	base := cfg.ProBase
	if base == "" {
		base = DefaultProBase
	}
	return &Reporter{
		key: cfg.ProKey, base: base, client: cfg.httpClient(), cls: cls, now: cfg.now,
		salt: hex.EncodeToString(b), rolls: map[rollKey]*rollVal{},
		mode: cfg.mode(), priceUSD: cfg.price(), payTo: cfg.PayTo, name: cfg.SiteName,
	}
}

// HashIP returns a short salted hash, so the dashboard counts distinct sources without raw IPs.
func (r *Reporter) HashIP(ip string) string {
	h := sha256.Sum256([]byte(r.salt + ip))
	return hex.EncodeToString(h[:8])
}

func (r *Reporter) record(h Hit, host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.host == "" {
		r.host = host
	}
	day := h.Time.UTC().Format("2006-01-02")
	k := rollKey{day, h.BotName, h.Class}
	v := r.rolls[k]
	if v == nil {
		v = &rollVal{sources: map[string]struct{}{}}
		r.rolls[k] = v
	}
	v.hits++
	if len(v.sources) < 5000 {
		v.sources[h.IPHash] = struct{}{}
	}
	switch h.Status {
	case "paid":
		v.paid++
		v.revenue += h.AmountUnits
		if len(r.settlements) < 5000 {
			r.settlements = append(r.settlements, settlementRow{
				TS: h.Time.UTC().Format("2006-01-02 15:04:05"), BotName: h.BotName, UAClass: h.Class, Path: h.Path,
				Rail: h.Rail, AmountUnits: h.AmountUnits, TxHash: h.Tx, Payer: h.Payer,
			})
		}
	case "unpaid":
		v.unpaid++
	case "rejected", "settle_failed":
		v.rejected++
	case "monitor":
		v.monitor++
		v.would += h.AmountUnits
	}
	// keep only today and yesterday
	cut := r.now().UTC().Add(-48 * time.Hour).Format("2006-01-02")
	for kk := range r.rolls {
		if kk.day < cut {
			delete(r.rolls, kk)
		}
	}
}

func (r *Reporter) request(ctx context.Context, method, path string, body any) (map[string]any, int, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "forgemesh-pay-per-crawl-go/"+Version+" ("+r.host+")")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var out map[string]any
	if json.Unmarshal(b, &out) != nil || out == nil {
		return nil, resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return out, resp.StatusCode, nil
}

// Verify checks the license key with the hosted service and reports whether it is active.
func (r *Reporter) Verify(ctx context.Context) (bool, error) {
	out, code, err := r.request(ctx, http.MethodPost, "/api/wp/license/verify", nil)
	ok := err == nil && code < 400
	if ok {
		if b, has := out["ok"].(bool); has {
			ok = b
		}
	}
	r.mu.Lock()
	r.verifiedAt, r.licenseOK = r.now(), ok
	r.mu.Unlock()
	return ok, err
}

// Sync pushes rollups and new settlements, and refreshes the intel feed once a day.
func (r *Reporter) Sync(ctx context.Context) error {
	r.mu.Lock()
	stale := r.verifiedAt.IsZero() || r.now().Sub(r.verifiedAt) > 24*time.Hour
	r.mu.Unlock()
	if stale {
		if _, err := r.Verify(ctx); err != nil {
			return err
		}
	}
	r.mu.Lock()
	if !r.licenseOK {
		r.mu.Unlock()
		return fmt.Errorf("license not active")
	}
	byDay := map[string][]map[string]any{}
	for k, v := range r.rolls {
		byDay[k.day] = append(byDay[k.day], map[string]any{
			"bot_name": k.bot, "ua_class": k.class, "hits": v.hits, "paid": v.paid, "unpaid": v.unpaid,
			"rejected": v.rejected, "monitor": v.monitor, "revenue_units": v.revenue, "would_units": v.would, "sources": len(v.sources),
		})
	}
	days := make([]string, 0, len(byDay))
	for d := range byDay {
		days = append(days, d)
	}
	sort.Strings(days)
	daily := []any{}
	for _, d := range days {
		daily = append(daily, map[string]any{"day": d, "rows": byDay[d]})
	}
	pending := append([]settlementRow{}, r.settlements...)
	payload := map[string]any{
		"site": map[string]any{
			"host": r.host, "url": "https://" + r.host + "/", "name": r.name, "plugin_version": Version,
			"mode": r.mode, "price_usd": r.priceUSD, "pay_to": r.payTo, "listed": false,
		},
		"daily": daily, "settlements": pending,
	}
	needIntel := r.intelAt.IsZero() || r.now().Sub(r.intelAt) > 24*time.Hour
	r.mu.Unlock()

	out, code, err := r.request(ctx, http.MethodPost, "/api/wp/ingest", payload)
	if err != nil {
		return err
	}
	if b, has := out["ok"].(bool); code >= 400 || (has && !b) {
		return fmt.Errorf("ingest rejected: HTTP %d", code)
	}
	r.mu.Lock()
	if len(r.settlements) >= len(pending) {
		r.settlements = r.settlements[len(pending):]
	}
	r.mu.Unlock()

	if needIntel {
		return r.pullIntel(ctx)
	}
	return nil
}

func (r *Reporter) pullIntel(ctx context.Context) error {
	out, code, err := r.request(ctx, http.MethodGet, "/api/wp/intel", nil)
	if err != nil || code >= 400 {
		return err
	}
	raw, _ := json.Marshal(out["agents"])
	var agents []Entry
	if json.Unmarshal(raw, &agents) != nil {
		return nil
	}
	valid := map[string]bool{}
	for _, c := range Classes() {
		valid[c] = true
	}
	clean := []Entry{}
	for _, a := range agents {
		if len(clean) >= 500 {
			break
		}
		if a.Name == "" || len(a.Match) == 0 || !valid[a.Class] {
			continue
		}
		if len(a.Name) > 64 {
			a.Name = a.Name[:64]
		}
		if len(a.Match) > 8 {
			a.Match = a.Match[:8]
		}
		for i, m := range a.Match {
			if len(m) > 64 {
				m = m[:64]
			}
			a.Match[i] = lower(m)
		}
		clean = append(clean, a)
	}
	r.cls.MergeCatalog(clean)
	r.mu.Lock()
	r.intelAt = r.now()
	r.mu.Unlock()
	return nil
}

func lower(s string) string { return string(bytes.ToLower([]byte(s))) }

// Run syncs hourly (first run after five minutes) until ctx is done.
func (r *Reporter) Run(ctx context.Context) {
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Sync(ctx)
			t.Reset(time.Hour)
		}
	}
}
