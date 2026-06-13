package lib

import (
	"fmt"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
)

// ExecuteParameterPhase constructs and enqueues URL-parameter injection test requests for each input URL.
//
// For each URL this function creates two test variants (one with an explicit "http://" scheme and one without),
// reserves a unique tracking id while holding trackMutex, records metadata in requestTracker[id] with InjectType
// "URL Parameter Injection", and increments the provided WaitGroup for each enqueued job. Each job sent to the
// jobs channel waits on rl before issuing the HTTP request and reports results through logActivity: an "ERROR"
// entry with status 0 and the error message on failure, or a "SENT" entry with the response status and the
// message "URL Parameter Phase Vector" on success.
//
// This function does not return a value; it performs side effects on the WaitGroup, trackCounter, requestTracker,
// and by sending closures to the jobs channel.
func ExecuteParameterPhase(
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
		for _, useScheme := range []bool{false, true} {
			trackMutex.Lock()
			*trackCounter++
			id := fmt.Sprintf("idx%d", *trackCounter)

			collabPayload := id + "." + collab
			if useScheme {
				collabPayload = "http://" + collabPayload
			}

			u := pkg.QsReplace(rawURL, collabPayload)
			requestTracker[id] = pkg.VulnerabilityMetadata{
				BaseURL:    rawURL,
				InjectType: "URL Parameter Injection",
			}
			trackMutex.Unlock()

			wg.Add(1)
			func(targetURL string) {
				jobs <- func() {
					defer wg.Done()
					rl.Wait()
					status, _, err := pkg.SendRequest(targetURL, pkg.BaseHeaders())
					if err != nil {
						logActivity("ERROR", targetURL, 0, err.Error())
						return
					}
					logActivity("SENT", targetURL, status, "URL Parameter Phase Vector")
				}
			}(u)
		}
	}
}
