// Package pkg provides shared infrastructure for the ressrf SSRF fuzzer: configuration
// parsing, HTTP request sending, rate limiting, payload file management, and Interactsh
// client session lifecycle. All scanning-phase packages (lib) import this package for
// common types and utilities.
package pkg

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/goflags"
)

//go:embed payloads.cfg
var defaultPayloads string

// Options holds all user-configurable parameters parsed from command-line flags.
type Options struct {
	InputFile    string
	CollabServer string
	Threads      int
	RateLimit    int
	OutDir       string
	ExtraHeader  string
	Silent       bool
	ColorBlind   bool
	Verbose      bool
}

// VulnerabilityMetadata stores the context of an injected payload so that out-of-band
// callbacks can be correlated back to the specific request and injection point.
type VulnerabilityMetadata struct {
	BaseURL    string
	InjectType string
	HeaderName string
}

var (
	// InputFile is the path to the file containing target URLs. Read from the -l flag.
	InputFile    *string
	// CollabServer is an optional custom collaboration server domain. Read from the -c flag.
	CollabServer *string
	// Threads is the number of concurrent worker goroutines. Read from the -t flag.
	Threads      *int
	// RateLimit is the maximum number of HTTP requests per second. Read from the -r flag.
	RateLimit    *int
	// OutDir is the directory path for output files (logs, findings). Read from the -o flag.
	OutDir       *string
	// ExtraHeader is an optional custom HTTP header in "Key: Value" format. Read from the -H flag.
	ExtraHeader  *string
	// Silent controls whether banners and progress messages are printed. Read from the -s flag.
	Silent       *bool
	// ColorBlind disables colored terminal output. Read from the -b flag.
	ColorBlind   *bool
	// Verbose enables live streaming of connection updates. Read from the -v flag.
	Verbose      *bool

	// PayloadsFile is the path to the payload configuration file, located at
	// ~/.config/ressrf/payloads.cfg. It is populated with embedded default vectors on first
	// use and user customisations are preserved across updates.
	PayloadsFile  = filepath.Join(os.Getenv("HOME"), ".config", "ressrf", "payloads.cfg")
	// HeadersInject is the list of HTTP header names that will be tested for SSRF
	// vulnerabilities. Each header is injected with a collaboration payload and the
	// scanner monitors for out-of-band callbacks.
	HeadersInject = []string{
		"Base-Url", "CF-Connecting_IP", "Client-IP", "Contact",
		"Forwarded", "From", "Http-Url", "Proxy-Host", "Proxy-Url",
		"Real-Ip", "Redirect", "Referer", "Referrer", "Request-Uri",
		"True-Client-IP", "Uri", "Url", "X-Client-IP", "X-Forward-For",
		"X-Forwarded-By", "X-Forwarded-For-Original", "X-Forwarded-For",
		"X-Forwarded-Host", "X-Forwarded-Server", "X-Forwarded",
		"X-Forwarder-For", "X-Host", "X-Http-Destinationurl",
		"X-Http-Host-Override", "X-Original-Remote-Addr", "X-Original-Url",
		"X-Originating-IP", "X-Proxy-Url", "X-Real-Ip", "X-Remote-Addr",
		"X-Rewrite-Url", "X-Wap-Profile",
	}
	// AltProtoRegex matches response bodies that indicate an alternate-protocol SSRF
	// vulnerability (e.g. cloud metadata endpoints, localhost references, or gopher/dict/file
	// scheme content). When the regex matches, the scanner reports an ALT-PROTO HIT.
	AltProtoRegex  = regexp.MustCompile(`169\.254\.169\.254|latest/meta-data|root:|127\.0\.0\.1|localhost|gopher://|dict://|file://`)
	// QsReplaceRegex matches the value portion of URL query parameters (the text after "="
	// up to the next "&" or end-of-string). It is used by QsReplace to substitute payloads
	// into query strings.
	QsReplaceRegex = regexp.MustCompile(`=([^?|&]*)`)
)

// EnsurePayloadsConfig ensures the payloads configuration file exists and contains the embedded default vectors.
//
// If the configured payload file does not exist, it will be created containing the embedded defaults.
// If the file exists, any default vectors not already present will be appended (with a separator) so existing
// user content is preserved. When `silent` is false a brief status message is printed.
//
// Errors are returned for filesystem failures such as directory creation, file reads, or writes.
func EnsurePayloadsConfig(silent bool) error {
	configDir := filepath.Dir(PayloadsFile)

	// Create ~/.config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	if _, err := os.Stat(PayloadsFile); os.IsNotExist(err) {
		return os.WriteFile(PayloadsFile, []byte(strings.TrimSpace(defaultPayloads)+"\n"), 0644)
	}

	existingContent, err := os.ReadFile(PayloadsFile)
	if err != nil {
		return err
	}
	existingStr := string(existingContent)

	var linesToAppend []string
	defaultLines := strings.Split(defaultPayloads, "\n")

	for _, line := range defaultLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(existingStr, line) {
			linesToAppend = append(linesToAppend, line)
		}
	}

	if len(linesToAppend) > 0 {
		if !silent {
			fmt.Printf("[INFO] SYNCING WORKSPACE: Appending %d new default payloads to %s\n", len(linesToAppend), PayloadsFile)
		}

		f, err := os.OpenFile(PayloadsFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		// Add a clean visual separator if appending new stuff to their custom file
		if !strings.HasSuffix(existingStr, "\n") {
			_, _ = f.WriteString("\n")
		}
		_, _ = f.WriteString("# Appended Missing Default Vectors\n")

		for _, line := range linesToAppend {
			if _, err := f.WriteString(line + "\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

// ParseOptions parses command-line flags into an Options value and initializes package-level option pointers.
//
// It validates the optional InputFile when provided (must exist, must not be a directory, must be non-empty).
// It also ensures the payloads configuration is present by running the sync routine and will return an error if that setup fails.
// Returns the populated *Options on success or a non-nil error if flag parsing, input validation, or config setup fails.
func ParseOptions() (*Options, error) {
	os.Args[0] = "ressrf"

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`ReSSRF - An advanced Out-of-Band and In-Band SSRF fuzzing scanner with dynamic request tracking.`)

	flagSet.CreateGroup("input", "Input Target Options",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "\tInput file containing target URLs (Optional if using stdin pipeline)"),
		flagSet.StringVarP(&options.CollabServer, "collab", "c", "", "\tCustom Interactsh/OAST collaboration server domain"),
	)

	flagSet.CreateGroup("runtime", "Performance & Optimization",
		flagSet.IntVarP(&options.Threads, "threads", "t", 20, "\tNumber of concurrent processing worker threads"),
		flagSet.IntVarP(&options.RateLimit, "rate", "r", 50, "\tMaximum global requests allowed per second"),
		flagSet.StringVarP(&options.ExtraHeader, "header", "H", "", "\tCustom injection headers e.g. \"Authorization: Bearer token\""),
	)

	flagSet.CreateGroup("optimization", "Display Options",
		flagSet.BoolVarP(&options.Silent, "silent", "s", false, "\tSuppress banner, phase notifications and summary stats"),
		flagSet.BoolVarP(&options.ColorBlind, "color-blind", "b", false, "\tDisable colored terminal output sequences completely"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "\tShow livestream of active connection updates and status codes"),
	)

	flagSet.CreateGroup("output", "Output Directories",
		flagSet.StringVarP(&options.OutDir, "outdir", "o", "output", "\tTarget folder to generate activity logs and vulnerabilities reports"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if options.InputFile != "" {
		fileInfo, err := os.Stat(options.InputFile)
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("[ERROR] Specified input file '%s' does not exist", options.InputFile)
		}
		if fileInfo.IsDir() {
			return nil, fmt.Errorf("[ERROR] '%s' is a directory, expected a regular file", options.InputFile)
		}
		if fileInfo.Size() == 0 {
			return nil, fmt.Errorf("[ERROR] Specified input file '%s' is empty", options.InputFile)
		}
	}

	// Automatically run the sync configuration pipeline seamlessly
	if err := EnsurePayloadsConfig(options.Silent); err != nil {
		return nil, fmt.Errorf("[ERROR] CONFIG SETUP ERROR: %v", err)
	}

	InputFile = &options.InputFile
	CollabServer = &options.CollabServer
	Threads = &options.Threads
	RateLimit = &options.RateLimit
	OutDir = &options.OutDir
	ExtraHeader = &options.ExtraHeader
	Silent = &options.Silent
	ColorBlind = &options.ColorBlind
	Verbose = &options.Verbose

	return options, nil
}
