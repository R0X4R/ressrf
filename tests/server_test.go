package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestRunMockServer(t *testing.T) {
	oastRe := regexp.MustCompile(`\.oast\.(pro|live|site|online|fun|me)`)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Phase 1: Real Vulnerable GET Parameter Processing

		for _, values := range r.URL.Query() {
			for _, val := range values {
				if oastRe.MatchString(val) {
					fmt.Printf("[🔥 MOCK VULN]: Executing true outbound fetch for parameter payload: %s\n", val)

					// Force the server to execute a real network callback over the internet
					go func(targetURL string) {
						if !strings.HasPrefix(targetURL, "http") {
							targetURL = "http://" + targetURL
						}
						_, _ = http.Get(targetURL)
					}(val)
				}
			}
		}

		// Phase 2: Real Vulnerable Header Processing
		headersToTrack := []string{"Base-Url", "X-Forwarded-For", "X-Real-Ip", "Referer"}
		for _, h := range headersToTrack {
			val := r.Header.Get(h)
			if val != "" && oastRe.MatchString(val) {
				fmt.Printf("[🔥 MOCK VULN]: Executing true outbound fetch for header payload: %s\n", val)

				// Force an outbound request from the header string
				go func(targetURL string) {
					if !strings.HasPrefix(targetURL, "http") {
						targetURL = "http://" + targetURL
					}
					_, _ = http.Get(targetURL)
				}(val)
			}
		}

		// Phase 3: Alternate Protocols Payload Check
		if strings.Contains(r.URL.Path, "internal") || r.URL.Query().Get("file") != "" {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\n127.0.0.1 localhost")
			return
		}

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK")
	})

	fmt.Println("[*] Mock Target Server listening on http://localhost:8081")
	if err := http.ListenAndServe(":8081", nil); err != nil {
		t.Fatalf("Server failed: %v\n", err)
	}
}
