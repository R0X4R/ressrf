package lib

import (
	"fmt"
	"strings"
	"sync"

	"github.com/R0X4R/ressrf/pkg"
	"github.com/fatih/color"
)

func ExecuteProtocolPhase(
	urls []string,
	collab string,
	rl *pkg.RateLimiter,
	jobs chan<- func(),
	wg *sync.WaitGroup,
	logActivity func(string, ...interface{}),
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
						logActivity("REQUEST ERROR - Alt Proto Target: %s | Err: %v", targetURL, err)
						return
					}
					logActivity("REQUEST SENT - Status: [%d] | Alt Proto Payload URL: %s", status, targetURL)

					if pkg.AltProtoRegex.MatchString(body) {
						displayLine := fmt.Sprintf("%s [%s] [%s]",
							targetURL, color.HiRedString("ALT-PROTO HIT"), color.HiMagentaString("Local Content Leak"))
						logStorageLine := fmt.Sprintf("%s [ALT-PROTO HIT] [Local Content Leak]", targetURL)

						fmt.Println(displayLine)
						pkg.AppendLine(*pkg.OutDir+"/findings.txt", logStorageLine)
						logActivity("VULNERABILITY IDENTIFIED - %s", logStorageLine)
					}
				}
			}(u)
		}
	}
}
