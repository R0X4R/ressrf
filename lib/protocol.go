package lib

import (
	"fmt"
	"strings"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
	"github.com/fatih/color"
)

// ExecuteProtocolPhase schedules protocol-bypass HTTP request jobs for every combination of the provided URLs and protocol payload templates.
//
// ExecuteProtocolPhase reads payload templates from pkg.PayloadsFile, substitutes `{COLLAB}` and `{COLLAB_URL}` with the provided collab value, and for each resulting payload–URL pair enqueues a job on the provided jobs channel. Each job waits on rl, sends the HTTP request, and reports activity via logActivity. If a request fails it is logged with an "ERROR" activity and not further processed; successful requests are logged as "SENT". When the response body matches pkg.AltProtoRegex the function prints a hit line, appends a findings entry to the file at *pkg.OutDir+"/findings.txt", and logs a vulnerability-identification activity.
//
// If reading pkg.PayloadsFile fails, the function optionally prints a skip message and returns without scheduling any jobs. The function increments wg for each scheduled job and ensures wg.Done() is called when a job completes.
func ExecuteProtocolPhase(
	urls []string,
	collab string,
	rl *pkg.RateLimiter,
	jobs chan<- func(),
	wg *sync.WaitGroup,
	logActivity func(string, string, int, string),
) {
	payloads, err := pkg.ReadLines(pkg.PayloadsFile)
	if err != nil {
		if !*pkg.Silent {
			fmt.Printf("[!] Skipping Protocol Phase: cannot read %s\n", pkg.PayloadsFile)
		}
		return
	}

	for _, rawPayload := range payloads {
		p := strings.ReplaceAll(rawPayload, "{COLLAB}", "RESSRF."+collab)
		p = strings.ReplaceAll(p, "{COLLAB_URL}", "http://RESSRF."+collab)
		for _, rawURL := range urls {
			u := pkg.QsReplace(rawURL, p)
			wg.Add(1)
			func(targetURL string) {
				jobs <- func() {
					defer wg.Done()
					rl.Wait()
					status, body, err := pkg.SendRequest(targetURL, pkg.BaseHeaders())

					if err != nil {
						logActivity("ERROR", targetURL, 0, err.Error())
						return
					}

					logActivity("SENT", targetURL, status, "Protocol Bypass Vector")

					if pkg.AltProtoRegex.MatchString(body) {
						displayLine := fmt.Sprintf("%s [%s] [%s]",
							targetURL, color.HiRedString("ALT-PROTO HIT"), color.HiMagentaString("Local Content Leak"))
						logStorageLine := fmt.Sprintf("%s [ALT-PROTO HIT] [Local Content Leak]", targetURL)

						fmt.Println(displayLine)
						pkg.AppendLine(*pkg.OutDir+"/findings.txt", logStorageLine)

						logActivity("SENT", targetURL, status, "VULNERABILITY IDENTIFIED: ALT-PROTO HIT Local Content Leak")
					}
				}
			}(u)
		}
	}
}
