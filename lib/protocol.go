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
