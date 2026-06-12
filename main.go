package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/R0X4R/ressrf/lib"
	"github.com/R0X4R/ressrf/pkg"
	"github.com/fatih/color"
	"github.com/projectdiscovery/interactsh/pkg/server"
)

func logActivity(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf("[%s] ", timestamp) + fmt.Sprintf(format, args...)
	pkg.AppendLine(*pkg.OutDir+"/activity.log", msg)
}

func logCallback(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf("[%s] ", timestamp) + fmt.Sprintf(format, args...)
	pkg.AppendLine(*pkg.OutDir+"/callback.log", msg)
}

func main() {
	_, err := pkg.ParseOptions()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *pkg.ColorBlind {
		color.NoColor = true
	}

	os.MkdirAll(*pkg.OutDir, 0755)

	urls, err := pkg.ReadLines(*pkg.InputFile)
	if err != nil || len(urls) == 0 {
		fmt.Printf("[-] Cannot read input file or file is empty: %s\n", *pkg.InputFile)
		os.Exit(1)
	}

	var collab string
	if *pkg.CollabServer == "" {
		collab, err = pkg.StartInteractsh()
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			os.Exit(1)
		}
		defer pkg.ClientInstance.Close()
	} else {
		collab = regexp.MustCompile(`https?://`).ReplaceAllString(*pkg.CollabServer, "")
	}

	if !*pkg.Silent {
		color.New(color.Bold, color.FgCyan).Println("\nReSSRF - Advanced In-Band and Out-of-Band SSRF Fuzzing Scanner with Dynamic Request Tracking")
		fmt.Printf("\n[%s] [%s: %s]\n\n",
			color.HiGreenString("LOADED %d URLS", len(urls)),
			color.HiYellowString("COLLAB SESSION"),
			collab,
		)
	}

	rl := pkg.NewRateLimiter(*pkg.RateLimit)
	jobs := make(chan func(), 2000)
	var wg sync.WaitGroup

	var trackMutex sync.Mutex
	requestTracker := make(map[string]pkg.VulnerabilityMetadata)
	trackCounter := 0

	uniqueHits := make(map[string]string)
	var hitsMutex sync.Mutex
	savedCount := 0
	idFinder := regexp.MustCompile(`idx\d+`)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !*pkg.Silent {
			fmt.Println(color.RedString("\n[!] INTERRUPT SIGNAL RECEIVED! FLUSING LOGS AND SHUTTING DOWN GRACEFULLY..."))
		}
		if pkg.ClientInstance != nil {
			pkg.ClientInstance.Close()
		}
		logActivity("SCAN TERMINATED - User aborted scan via Interrupt signal.")
		logCallback("SCAN TERMINATED - User aborted scan via Interrupt signal.")
		os.Exit(0)
	}()

	if pkg.ClientInstance != nil {
		err = pkg.ClientInstance.StartPolling(5*time.Second, func(evt *server.Interaction) {
			logLine := fmt.Sprintf("OOB INTERACTION - Protocol: %s | Host: %s", evt.Protocol, evt.FullId)
			if evt.Protocol == "dns" {
				logLine += fmt.Sprintf(" (Type: %s)", evt.QType)
			}
			logCallback("%s", logLine)

			hitsMutex.Lock()
			savedCount++

			normalizedId := strings.ToLower(evt.FullId)
			if foundID := idFinder.FindString(normalizedId); foundID != "" {
				trackMutex.Lock()
				meta, exists := requestTracker[foundID]
				trackMutex.Unlock()

				if exists {
					var displayLine, logStorageLine string
					if meta.HeaderName != "" {
						displayLine = fmt.Sprintf("%s [%s] [%s] [%s]",
							meta.BaseURL, color.HiBlueString("LIVE OOB HIT"), color.HiMagentaString(meta.InjectType), color.CyanString(meta.HeaderName))
						logStorageLine = fmt.Sprintf("%s [LIVE OOB HIT] [%s] [%s]", meta.BaseURL, meta.InjectType, meta.HeaderName)
					} else {
						displayLine = fmt.Sprintf("%s [%s] [%s]",
							meta.BaseURL, color.HiBlueString("LIVE OOB HIT"), color.HiMagentaString(meta.InjectType))
						logStorageLine = fmt.Sprintf("%s [LIVE OOB HIT] [%s]", meta.BaseURL, meta.InjectType)
					}

					if _, alreadyHit := uniqueHits[logStorageLine]; !alreadyHit {
						uniqueHits[logStorageLine] = displayLine
						fmt.Println(displayLine)
						pkg.AppendLine(*pkg.OutDir+"/findings.txt", logStorageLine)
					}
				}
			}
			hitsMutex.Unlock()
		})
		if err != nil && !*pkg.Silent {
			fmt.Printf("[-] FAILED TO LAUNCH LIVE TRANSACTION POLLER: %v\n", err)
		}
	}

	for i := 0; i < *pkg.Threads; i++ {
		go func() {
			for job := range jobs {
				job()
			}
		}()
	}

	lib.ExecuteHeaderPhase(urls, collab, rl, jobs, &wg, &trackMutex, &trackCounter, requestTracker, logActivity)
	lib.ExecuteParameterPhase(urls, collab, rl, jobs, &wg, &trackMutex, &trackCounter, requestTracker, logActivity)
	lib.ExecuteProtocolPhase(urls, collab, rl, jobs, &wg, logActivity)

	wg.Wait()
	close(jobs)

	if !*pkg.Silent {
		color.New(color.Bold, color.FgCyan).Print("\n[*] SCANNING COMPLETE. KEEPING SESSION OPEN 20s FOR REMAINING PAYLOADS TO LAND.\n")
	}
	time.Sleep(20 * time.Second)

	absPath, pathErr := filepath.Abs(*pkg.OutDir)
	if pathErr != nil {
		absPath = *pkg.OutDir
	}

	if !*pkg.Silent {
		fmt.Println("\nOOB CALLBACK RESULTS:")
	}

	hitsMutex.Lock()
	if len(uniqueHits) == 0 {
		fmt.Println("[-] NO OUT-OF-BOUND INTERACTIONS CAPTURED BY THE SERVER.")
	} else {
		for _, renderedLine := range uniqueHits {
			fmt.Println(renderedLine)
		}
	}

	if !*pkg.Silent {
		fmt.Printf("\n[%s] [%s: %s]\n",
			color.HiGreenString("TOTAL TRANSACTION HITS %d", savedCount),
			color.HiCyanString("OUTPUT"),
			absPath,
		)
	}
	hitsMutex.Unlock()
}
