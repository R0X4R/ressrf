package pkg

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HttpClient is the shared HTTP client used for all scan requests. It has a 10-second
// timeout and is configured to not follow redirects (ErrUseLastResponse) so that the
// scanner can inspect every intermediate response.
var HttpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// RateLimiter controls the rate of outgoing HTTP requests using a time.Ticker. Call Wait
// before each request to stay within the configured requests-per-second limit.
type RateLimiter struct{ Ticker *time.Ticker }

// NewRateLimiter creates a RateLimiter that allows up to rps requests per second. The
// rate is evenly spaced: each call to Wait blocks for 1/rps seconds.
func NewRateLimiter(rps int) *RateLimiter {
	return &RateLimiter{time.NewTicker(time.Second / time.Duration(rps))}
}

// Wait blocks until the next tick according to the rate limiter's configured requests-per-
// second interval. It should be called once before each HTTP request.
func (r *RateLimiter) Wait() { <-r.Ticker.C }

// QsReplace substitutes the first value in every URL query parameter with the given
// URL-escaped payload. It replaces the right-hand side of "=" in query strings, so
// "?foo=bar&baz=qux" with payload "p" becomes "?foo=p&baz=p".
func QsReplace(rawURL, payload string) string {
	return QsReplaceRegex.ReplaceAllString(rawURL, "="+url.QueryEscape(payload))
}

// BaseHeaders returns a default set of HTTP headers used for scan requests. It always
// includes a User-Agent header. If the global ExtraHeader flag is set, it is parsed as
// "Key: Value" and added to the returned map.
func BaseHeaders() map[string]string {
	h := map[string]string{"User-Agent": "Mozilla/5.0 (compatible; SSRFCheck/1.0)"}
	if *ExtraHeader != "" {
		if parts := strings.SplitN(*ExtraHeader, ":", 2); len(parts) == 2 {
			h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return h
}

// SendRequest issues an HTTP GET request to the target URL with the given headers. It
// returns the HTTP status code, the response body (truncated to 4096 bytes), and any
// transport-level error. Redirects are not followed (see HttpClient).
func SendRequest(targetURL string, headers map[string]string) (int, string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := HttpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), nil
}
