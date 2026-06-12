package pkg

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var HttpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 100,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type RateLimiter struct{ Ticker *time.Ticker }

func NewRateLimiter(rps int) *RateLimiter {
	return &RateLimiter{time.NewTicker(time.Second / time.Duration(rps))}
}

func (r *RateLimiter) Wait() { <-r.Ticker.C }

func QsReplace(rawURL, payload string) string {
	return QsReplaceRegex.ReplaceAllString(rawURL, "="+url.QueryEscape(payload))
}

func BaseHeaders() map[string]string {
	h := map[string]string{"User-Agent": "Mozilla/5.0 (compatible; SSRFCheck/1.0)"}
	if *ExtraHeader != "" {
		if parts := strings.SplitN(*ExtraHeader, ":", 2); len(parts) == 2 {
			h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return h
}

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
