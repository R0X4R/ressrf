package main

import (
	"bufio"
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

// logActivity writes a timestamped activity entry to the activity.log file and, when verbose and not silent, prints a colored console message.
// For evtType == "ERROR", it records an "UNABLE TO CONNECT" entry including details; otherwise it records a "REQ SENT" entry including status, target, and optional details.
// The console output colorizes the status (green for 2xx, cyan for 3xx, yellow for others) and the log is appended to (*pkg.OutDir)/activity.log.
func logActivity(evtType string, target string, status int, details string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var msg, consoleMsg string

	if evtType == "ERROR" {
		msg = fmt.Sprintf("[%s] [UNABLE TO CONNECT] Target: %s | Details: %s", timestamp, target, details)
		consoleMsg = fmt.Sprintf("[%s] %s Target: %s", timestamp, color.RedString("[UNABLE TO CONNECT]"), target)
	} else {
		msg = fmt.Sprintf("[%s] [REQ SENT] Status: [%d] | Target: %s", timestamp, status, target)
		if details != "" {
			msg += " | " + details
		}

		statusStr := fmt.Sprintf("[%d]", status)
		if status >= 200 && status < 300 {
			statusStr = color.GreenString("[%d]", status)
		} else if status >= 300 && status < 400 {
			statusStr = color.CyanString("[%d]", status)
		} else {
			statusStr = color.YellowString("[%d]", status)
		}
		consoleMsg = fmt.Sprintf("[%s] %s STATUS %s == %s", timestamp, color.BlueString("[REQ SENT]"), statusStr, target)
	}

	pkg.AppendLine(*pkg.OutDir+"/activity.log", msg)

	if *pkg.Verbose && !*pkg.Silent {
		fmt.Println(consoleMsg)
	}
}

// logCallback appends a timestamped log line, formatted with the provided printf-style
// format and arguments, to the callback.log file in the configured output directory.
func logCallback(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf("[%s] ", timestamp) + fmt.Sprintf(format, args...)
	pkg.AppendLine(*pkg.OutDir+"/callback.log", msg)
}

// hasStdinData reports whether standard input has data available (i.e., stdin is not a terminal).
// It returns true when stdin is not a character device, and false if stdin is a terminal or if Stat() fails.
func hasStdinData() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// main is the program entry point that orchestrates configuration parsing, target collection,
// collaboration session initialization, concurrent scanning phases, out-of-band callback polling,
// and final result reporting.
//
// It parses CLI options and prepares the output directory, sources target URLs from stdin
// when available or from the configured input file, and either starts an Interactsh client
// or normalizes a provided collab server string. It launches worker goroutines, installs an
// interrupt handler that cleans up and logs a termination event, and starts a poller to
// process out-of-band interactions which are recorded to findings and activity logs.
// The function executes header, parameter, and protocol scan phases, waits for completion,
// keeps the session open for a short grace period to collect late callbacks, and then
// prints and stores summarized OOB results.
//
// The function terminates the process on fatal configuration or runtime errors (printing
// an error message before exiting).
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

	var urls []string

	if hasStdinData() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("[!] ERROR READING STANDARD INPUT STREAM: %v\n", err)
			os.Exit(1)
		}

	} else {
		if *pkg.InputFile == "" {
			fmt.Println("[!] ERROR: No targets provided. Pipeline urls via stdin or specify an input file using -l <file>")
			os.Exit(1)
		}
		urls, err = pkg.ReadLines(*pkg.InputFile)
		if err != nil || len(urls) == 0 {
			fmt.Printf("[!] ERROR: Cannot read input file or file is empty: %s\n", *pkg.InputFile)
			os.Exit(1)
		}
	}

	var collab string
	if *pkg.CollabServer == "" {
		collab, err = pkg.StartInteractsh()
		if err != nil {
			fmt.Printf("[!] ERROR: FAILED TO START INTERACTSH CLIENT: %v\n", err)
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
			fmt.Println(color.RedString("\n[!] INTERRUPT SIGNAL RECEIVED! FLUSHING LOGS AND SHUTTING DOWN GRACEFULLY..."))
		}
		if pkg.ClientInstance != nil {
			pkg.ClientInstance.Close()
		}
		logActivity("SCAN TERMINATED", "USER ABORTED SCAN VIA INTERRUPT SIGNAL", 0, "")
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
						if *pkg.Verbose {
							fmt.Print("\n" + displayLine + "\n\n")
						} else {
							fmt.Println(displayLine)
						}
						pkg.AppendLine(*pkg.OutDir+"/findings.txt", logStorageLine)
					}
				}
			}
			hitsMutex.Unlock()
		})
		if err != nil && !*pkg.Silent {
			fmt.Printf("[!] FAILED TO LAUNCH LIVE TRANSACTION POLLER: %v\n", err)
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
