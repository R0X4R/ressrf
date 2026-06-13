package lib

import (
	"fmt"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
)

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
