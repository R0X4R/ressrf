package lib

import (
	"fmt"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
)

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
