package paypercrawl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Verified is the tri-state result of a reverse-DNS check.
type Verified int

const (
	// VerifiedUnknown means no check ran, or DNS was unavailable (the claim is kept).
	VerifiedUnknown Verified = iota
	// VerifiedYes means the IP reverse-resolves to the operator's domain and forward-resolves back.
	VerifiedYes
	// VerifiedNo means the claim failed verification.
	VerifiedNo
)

// Classification is the answer to "who is asking".
type Classification struct {
	Class         string // human, search, social, monitor, seo, ai, automation, bot
	Name          string // catalog name, or the first UA token for unknown bots
	Verified      Verified
	Impersonation bool // claimed a search engine and failed reverse DNS
}

var (
	genericBotRe = regexp.MustCompile(`(?i)\b(bot|crawler|spider|scraper|fetcher|crawl|agent|archiver|indexer)\b`)
	browserRe    = regexp.MustCompile(`(chrome|safari|firefox|edg|opera|opr|msie|trident|samsungbrowser|ucbrowser)`)
	shortNameRe  = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)`)
)

// Classifier holds the catalog and a day-long reverse-DNS cache.
type Classifier struct {
	mu       sync.RWMutex
	catalog  []Entry
	resolver Resolver
	cacheMu  sync.Mutex
	cache    map[string]rdnsEntry
	now      func() time.Time
}

type rdnsEntry struct {
	v   Verified
	exp time.Time
}

// NewClassifier returns a classifier with the shipped catalog. A nil resolver means net.DefaultResolver.
func NewClassifier(r Resolver) *Classifier {
	if r == nil {
		r = net.DefaultResolver
	}
	return &Classifier{catalog: Catalog(), resolver: r, cache: map[string]rdnsEntry{}, now: time.Now}
}

var defaultClassifier = NewClassifier(nil)

// Classify classifies one request with the shipped catalog and the system resolver.
// headers is a map with lowercased keys (accept, ...); ip may be empty.
func Classify(ua string, headers map[string]string, ip string) Classification {
	return defaultClassifier.Classify(ua, headers, ip)
}

// MergeCatalog merges extra entries (for example the Pro intel feed): new names are
// appended, known names get their match list extended and verify list replaced.
func (c *Classifier) MergeCatalog(extra []Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := map[string]int{}
	for i, e := range c.catalog {
		idx[e.Name] = i
	}
	for _, a := range extra {
		if i, ok := idx[a.Name]; ok {
			have := map[string]bool{}
			for _, m := range c.catalog[i].Match {
				have[m] = true
			}
			merged := append([]string{}, c.catalog[i].Match...)
			for _, m := range a.Match {
				if !have[m] {
					merged = append(merged, m)
				}
			}
			c.catalog[i].Match = merged
			if len(a.Verify) > 0 {
				c.catalog[i].Verify = a.Verify
			}
		} else {
			idx[a.Name] = len(c.catalog)
			c.catalog = append(c.catalog, a)
		}
	}
}

// Classify classifies one request.
func (c *Classifier) Classify(ua string, headers map[string]string, ip string) Classification {
	uaL := strings.ToLower(strings.TrimSpace(ua))

	c.mu.RLock()
	cat := c.catalog
	c.mu.RUnlock()
	for _, e := range cat {
		for _, needle := range e.Match {
			if !strings.Contains(uaL, needle) {
				continue
			}
			res := Classification{Class: e.Class, Name: e.Name}
			if len(e.Verify) > 0 && ip != "" {
				res.Verified = c.verifyRDNS(ip, e.Verify)
				if res.Verified == VerifiedNo {
					res.Class = "automation"
					res.Impersonation = true
				}
			}
			return res
		}
	}

	if uaL == "" {
		return Classification{Class: "automation", Name: "Empty User-Agent"}
	}
	if genericBotRe.MatchString(uaL) {
		return Classification{Class: "bot", Name: shortName(ua)}
	}
	if strings.Contains(uaL, "mozilla/") && browserRe.MatchString(uaL) {
		accept := strings.ToLower(headers["accept"])
		// A real navigation sends text/html; an API-ish Accept with a browser UA is a tool.
		if accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") && !strings.Contains(accept, "image/") {
			return Classification{Class: "automation", Name: "Browser-UA tool"}
		}
		return Classification{Class: "human"}
	}
	return Classification{Class: "bot", Name: shortName(ua)}
}

func shortName(ua string) string {
	ua = strings.TrimSpace(ua)
	n := ua
	if m := shortNameRe.FindString(ua); m != "" {
		n = m
	}
	if len(n) > 60 {
		n = n[:60]
	}
	return n
}

// verifyRDNS does a reverse lookup, checks the suffix, then a forward lookup that
// must include the original IP. A missing PTR is a definite no; a DNS outage is unknown.
func (c *Classifier) verifyRDNS(ip string, suffixes []string) Verified {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return VerifiedUnknown
	}
	addr = addr.Unmap()
	key := addr.String() + "|" + strings.Join(suffixes, ",")
	c.cacheMu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Before(e.exp) {
		c.cacheMu.Unlock()
		return e.v
	}
	c.cacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := VerifiedUnknown
	names, err := c.resolver.LookupAddr(ctx, addr.String())
	switch {
	case err != nil:
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			result = VerifiedNo // no PTR at all: not a search engine
		}
	case len(names) == 0:
		result = VerifiedNo
	default:
		result = VerifiedNo
		for _, n := range names {
			host := strings.ToLower(strings.TrimRight(n, "."))
			ok := false
			for _, s := range suffixes {
				if strings.HasSuffix(host, strings.ToLower(s)) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
			fwd, ferr := c.resolver.LookupHost(ctx, host)
			if ferr != nil {
				continue
			}
			for _, f := range fwd {
				if fa, perr := netip.ParseAddr(f); perr == nil && fa.Unmap() == addr {
					result = VerifiedYes
					break
				}
			}
			if result == VerifiedYes {
				break
			}
		}
	}
	if result != VerifiedUnknown {
		c.cacheMu.Lock()
		if len(c.cache) > 10000 {
			c.cache = map[string]rdnsEntry{}
		}
		c.cache[key] = rdnsEntry{v: result, exp: c.now().Add(24 * time.Hour)}
		c.cacheMu.Unlock()
	}
	return result
}
