package paypercrawl

// Entry is one known crawler. Patterns are lowercase substrings of the
// User-Agent; the first entry that matches wins. Verify lists reverse-DNS
// suffixes that prove the operator (search engines publish these); a claim that
// fails verification is demoted to "automation".
type Entry struct {
	Name   string   `json:"name"`
	Class  string   `json:"class"`
	Match  []string `json:"match"`
	Verify []string `json:"verify,omitempty"`
}

// Classes returns the crawler classes in policy order.
func Classes() []string {
	return []string{"human", "search", "social", "monitor", "seo", "ai", "automation", "bot"}
}

// Catalog returns a copy of the shipped catalog (same list as the WordPress plugin).
func Catalog() []Entry {
	out := make([]Entry, len(shipped))
	copy(out, shipped)
	return out
}

var shipped = []Entry{
	// Search engines (free by default; verified by rDNS).
	{Name: "Googlebot", Class: "search", Match: []string{"googlebot"}, Verify: []string{".googlebot.com", ".google.com"}},
	{Name: "Google-InspectionTool", Class: "search", Match: []string{"google-inspectiontool"}, Verify: []string{".googlebot.com", ".google.com"}},
	{Name: "GoogleOther", Class: "ai", Match: []string{"googleother"}, Verify: []string{".googlebot.com", ".google.com"}},
	{Name: "Bingbot", Class: "search", Match: []string{"bingbot"}, Verify: []string{".search.msn.com"}},
	{Name: "DuckDuckBot", Class: "search", Match: []string{"duckduckbot"}},
	{Name: "Applebot", Class: "search", Match: []string{"applebot"}, Verify: []string{".applebot.apple.com"}},
	{Name: "YandexBot", Class: "search", Match: []string{"yandexbot", "yandex.com/bots"}, Verify: []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
	{Name: "Baiduspider", Class: "search", Match: []string{"baiduspider"}, Verify: []string{".baidu.com", ".baidu.jp"}},
	{Name: "Yahoo Slurp", Class: "search", Match: []string{"yahoo! slurp"}, Verify: []string{".crawl.yahoo.net"}},
	{Name: "SeznamBot", Class: "search", Match: []string{"seznambot"}, Verify: []string{".seznam.cz"}},
	{Name: "Qwantbot", Class: "search", Match: []string{"qwantbot", "qwantify"}},

	// AI crawlers and assistants (paid by default).
	{Name: "GPTBot", Class: "ai", Match: []string{"gptbot"}},
	{Name: "ChatGPT-User", Class: "ai", Match: []string{"chatgpt-user"}},
	{Name: "OAI-SearchBot", Class: "ai", Match: []string{"oai-searchbot"}},
	{Name: "ClaudeBot", Class: "ai", Match: []string{"claudebot", "anthropic-ai"}},
	{Name: "Claude-User", Class: "ai", Match: []string{"claude-user"}},
	{Name: "Claude-SearchBot", Class: "ai", Match: []string{"claude-searchbot"}},
	{Name: "PerplexityBot", Class: "ai", Match: []string{"perplexitybot"}},
	{Name: "Perplexity-User", Class: "ai", Match: []string{"perplexity-user"}},
	{Name: "Google-Extended", Class: "ai", Match: []string{"google-extended"}},
	{Name: "Gemini-Deep-Research", Class: "ai", Match: []string{"gemini-deep-research"}},
	{Name: "Amazonbot", Class: "ai", Match: []string{"amazonbot"}},
	{Name: "Applebot-Extended", Class: "ai", Match: []string{"applebot-extended"}},
	{Name: "Meta-ExternalAgent", Class: "ai", Match: []string{"meta-externalagent", "meta-externalfetcher", "facebookbot"}},
	{Name: "Bytespider", Class: "ai", Match: []string{"bytespider", "tiktokspider"}},
	{Name: "CCBot", Class: "ai", Match: []string{"ccbot"}},
	{Name: "cohere-ai", Class: "ai", Match: []string{"cohere-ai", "cohere-training-data-crawler"}},
	{Name: "MistralAI-User", Class: "ai", Match: []string{"mistralai-user"}},
	{Name: "DuckAssistBot", Class: "ai", Match: []string{"duckassistbot"}},
	{Name: "YouBot", Class: "ai", Match: []string{"youbot"}},
	{Name: "Diffbot", Class: "ai", Match: []string{"diffbot"}},
	{Name: "ImagesiftBot", Class: "ai", Match: []string{"imagesiftbot"}},
	{Name: "Omgili", Class: "ai", Match: []string{"omgili", "webzio"}},
	{Name: "AI2Bot", Class: "ai", Match: []string{"ai2bot"}},
	{Name: "PetalBot", Class: "ai", Match: []string{"petalbot"}},
	{Name: "Timpibot", Class: "ai", Match: []string{"timpibot"}},
	{Name: "iAskBot", Class: "ai", Match: []string{"iaskspider", "iaskbot"}},
	{Name: "Kagibot", Class: "ai", Match: []string{"kagibot"}},
	{Name: "DeepSeekBot", Class: "ai", Match: []string{"deepseekbot"}},
	{Name: "Grok", Class: "ai", Match: []string{"xai-grok", "grokbot"}},
	{Name: "Brave Search", Class: "ai", Match: []string{"bravebot"}},
	{Name: "Firecrawl", Class: "ai", Match: []string{"firecrawl"}},
	{Name: "Jina Reader", Class: "ai", Match: []string{"jina", "readerbot"}},
	{Name: "Exa", Class: "ai", Match: []string{"exabot", "exa.ai"}},
	{Name: "Tavily", Class: "ai", Match: []string{"tavily"}},
	{Name: "Browserbase", Class: "ai", Match: []string{"browserbase"}},

	// SEO crawlers (paid by default: commercial, high volume).
	{Name: "AhrefsBot", Class: "seo", Match: []string{"ahrefsbot"}},
	{Name: "SemrushBot", Class: "seo", Match: []string{"semrushbot"}},
	{Name: "MJ12bot", Class: "seo", Match: []string{"mj12bot"}},
	{Name: "DotBot", Class: "seo", Match: []string{"dotbot"}},
	{Name: "DataForSeoBot", Class: "seo", Match: []string{"dataforseobot"}},
	{Name: "BLEXBot", Class: "seo", Match: []string{"blexbot"}},
	{Name: "Screaming Frog", Class: "seo", Match: []string{"screaming frog"}},
	{Name: "SiteAuditBot", Class: "seo", Match: []string{"siteauditbot"}},

	// Social link previews (free by default: humans see these).
	{Name: "Facebook preview", Class: "social", Match: []string{"facebookexternalhit"}},
	{Name: "Twitterbot", Class: "social", Match: []string{"twitterbot"}},
	{Name: "LinkedInBot", Class: "social", Match: []string{"linkedinbot"}},
	{Name: "Slackbot", Class: "social", Match: []string{"slackbot", "slack-imgproxy"}},
	{Name: "Discordbot", Class: "social", Match: []string{"discordbot"}},
	{Name: "TelegramBot", Class: "social", Match: []string{"telegrambot"}},
	{Name: "WhatsApp", Class: "social", Match: []string{"whatsapp"}},
	{Name: "Pinterestbot", Class: "social", Match: []string{"pinterestbot", "pinterest/"}},
	{Name: "Redditbot", Class: "social", Match: []string{"redditbot"}},
	{Name: "Mastodon", Class: "social", Match: []string{"mastodon"}},
	{Name: "Bluesky", Class: "social", Match: []string{"bluesky cardyb"}},
	{Name: "iMessage preview", Class: "social", Match: []string{"facebot twitterbot"}},

	// Monitors and feed readers (free by default).
	{Name: "UptimeRobot", Class: "monitor", Match: []string{"uptimerobot"}},
	{Name: "Pingdom", Class: "monitor", Match: []string{"pingdom"}},
	{Name: "StatusCake", Class: "monitor", Match: []string{"statuscake"}},
	{Name: "Better Uptime", Class: "monitor", Match: []string{"betteruptime", "better uptime"}},
	{Name: "Feed reader", Class: "monitor", Match: []string{"feedly", "feedbin", "inoreader", "newsblur", "feedfetcher"}},
	{Name: "Internet Archive", Class: "monitor", Match: []string{"archive.org_bot", "ia_archiver"}},
	{Name: "WordPress", Class: "monitor", Match: []string{"wordpress/"}},

	// Generic automation (paid by default).
	{Name: "curl", Class: "automation", Match: []string{"curl/"}},
	{Name: "wget", Class: "automation", Match: []string{"wget/"}},
	{Name: "python-requests", Class: "automation", Match: []string{"python-requests", "python-urllib", "aiohttp", "httpx/"}},
	{Name: "Scrapy", Class: "automation", Match: []string{"scrapy"}},
	{Name: "Go-http-client", Class: "automation", Match: []string{"go-http-client"}},
	{Name: "Node fetch", Class: "automation", Match: []string{"node-fetch", "undici", "axios/", "got ("}},
	{Name: "Java HTTP", Class: "automation", Match: []string{"java/", "okhttp", "apache-httpclient"}},
	{Name: "Headless browser", Class: "automation", Match: []string{"headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium"}},
	{Name: "HTTPie", Class: "automation", Match: []string{"httpie"}},
	{Name: "PostmanRuntime", Class: "automation", Match: []string{"postmanruntime"}},
	{Name: "libwww", Class: "automation", Match: []string{"libwww", "lwp-trivial"}},
	{Name: "x402 client", Class: "automation", Match: []string{"x402", "mpp/"}},
}
