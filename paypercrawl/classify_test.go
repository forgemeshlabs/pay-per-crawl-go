package paypercrawl

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestClassifyCases(t *testing.T) {
	googlebotRes := fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	}
	cls := NewClassifier(googlebotRes)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
	gb := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	cases := []struct {
		name    string
		ua, ip  string
		hdr     map[string]string
		class   string
		bot     string
		ver     Verified
		imperso bool
	}{
		{"chrome is human", chrome, "", map[string]string{"accept": "text/html,application/xhtml+xml"}, "human", "", VerifiedUnknown, false},
		{"gptbot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "", nil, "ai", "GPTBot", VerifiedUnknown, false},
		{"claudebot", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "", nil, "ai", "ClaudeBot", VerifiedUnknown, false},
		{"curl", "curl/8.5.0", "", nil, "automation", "curl", VerifiedUnknown, false},
		{"empty UA", "", "", nil, "automation", "Empty User-Agent", VerifiedUnknown, false},
		{"facebook preview", "facebookexternalhit/1.1", "", nil, "social", "Facebook preview", VerifiedUnknown, false},
		{"ahrefs", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "", nil, "seo", "AhrefsBot", VerifiedUnknown, false},
		{"unknown bot word", "SomethingNewCrawler/2.0 (+https://example.com/bot)", "", nil, "bot", "SomethingNewCrawler", VerifiedUnknown, false},
		{"googlebot real IP verifies", gb, "66.249.66.1", nil, "search", "Googlebot", VerifiedYes, false},
		{"googlebot fake IP demoted", gb, "203.0.113.9", nil, "automation", "Googlebot", VerifiedNo, true},
		{"googlebot no IP keeps claim", gb, "", nil, "search", "Googlebot", VerifiedUnknown, false},
		{"browser UA with json accept is a tool", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36", "", map[string]string{"accept": "application/json"}, "automation", "Browser-UA tool", VerifiedUnknown, false},
		{"duckduckbot has no rDNS list", "DuckDuckBot/1.1", "203.0.113.9", nil, "search", "DuckDuckBot", VerifiedUnknown, false},
		{"non-browser non-bot string", "weird-thing", "", nil, "bot", "weird-thing", VerifiedUnknown, false},
		{"uptimerobot", "Mozilla/5.0+(compatible; UptimeRobot/2.0)", "", nil, "monitor", "UptimeRobot", VerifiedUnknown, false},
		{"go-http-client", "Go-http-client/1.1", "", nil, "automation", "Go-http-client", VerifiedUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cls.Classify(c.ua, c.hdr, c.ip)
			if got.Class != c.class || got.Name != c.bot || got.Verified != c.ver || got.Impersonation != c.imperso {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestRDNSOutageKeepsClaim(t *testing.T) {
	cls := NewClassifier(fakeResolver{err: errors.New("i/o timeout")})
	got := cls.Classify("Googlebot/2.1", nil, "66.249.66.1")
	if got.Class != "search" || got.Verified != VerifiedUnknown {
		t.Fatalf("DNS outage must not demote: %+v", got)
	}
}

func TestRDNSForwardMismatchAndCache(t *testing.T) {
	calls := 0
	res := &countingResolver{fakeResolver: fakeResolver{
		ptr: map[string][]string{"203.0.113.9": {"crawl.googlebot.com"}},
		fwd: map[string][]string{"crawl.googlebot.com": {"66.249.66.1"}}, // forward does not match
	}, n: &calls}
	cls := NewClassifier(res)
	for i := 0; i < 3; i++ {
		if got := cls.Classify("Googlebot", nil, "203.0.113.9"); !got.Impersonation {
			t.Fatalf("spoofed PTR must fail forward check: %+v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("result should be cached, resolver called %d times", calls)
	}
}

type countingResolver struct {
	fakeResolver
	n *int
}

func (c *countingResolver) LookupAddr(ctx2 context.Context, a string) ([]string, error) {
	*c.n++
	return c.fakeResolver.LookupAddr(ctx2, a)
}

func TestCatalogShape(t *testing.T) {
	cat := Catalog()
	if len(cat) != 85 {
		t.Fatalf("catalog has %d entries, the PHP reference ships 85", len(cat))
	}
	valid := map[string]bool{}
	for _, c := range Classes() {
		valid[c] = true
	}
	for _, e := range cat {
		if !valid[e.Class] || len(e.Match) == 0 {
			t.Errorf("bad entry %+v", e)
		}
		for _, m := range e.Match {
			if m != strings.ToLower(m) {
				t.Errorf("%s: match %q must be lowercase", e.Name, m)
			}
		}
	}
}

func TestMergeCatalog(t *testing.T) {
	cls := NewClassifier(nil)
	cls.MergeCatalog([]Entry{
		{Name: "GPTBot", Class: "ai", Match: []string{"gptbot", "gptbot-next"}},
		{Name: "Brand New Crawler", Class: "seo", Match: []string{"brandnewcrawler/"}},
	})
	if g := cls.Classify("Mozilla/5.0 brandnewcrawler/1.0", nil, ""); g.Class != "seo" || g.Name != "Brand New Crawler" {
		t.Fatalf("new agent not appended: %+v", g)
	}
	if g := cls.Classify("gptbot-next/9", nil, ""); g.Name != "GPTBot" {
		t.Fatalf("known agent match list not extended: %+v", g)
	}
	n := 0
	for _, e := range cls.catalog {
		if e.Name == "GPTBot" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("GPTBot duplicated %d times", n)
	}
}

func TestPolicy(t *testing.T) {
	c := Config{BotOverrides: map[string]string{"GPTBot": "block", "curl": "free", "x": "bogus"}, ClassPolicy: map[string]string{"seo": "free"}}
	for _, tc := range []struct {
		cl   Classification
		want string
	}{
		{Classification{Class: "ai", Name: "GPTBot"}, "block"},
		{Classification{Class: "automation", Name: "curl"}, "free"},
		{Classification{Class: "seo", Name: "AhrefsBot"}, "free"},
		{Classification{Class: "ai", Name: "ClaudeBot"}, "paid"},
		{Classification{Class: "search", Name: "Bingbot"}, "free"},
		{Classification{Class: "bot", Name: "x"}, "paid"},
	} {
		if got := c.Policy(tc.cl); got != tc.want {
			t.Errorf("%+v: got %s want %s", tc.cl, got, tc.want)
		}
	}
}
