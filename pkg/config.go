package pkg

import (
	_ "embed" // Required for compile-time asset embedding
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/goflags"
)

//go:embed payloads.cfg
var defaultPayloads string

type Options struct {
	InputFile    string
	CollabServer string
	Threads      int
	RateLimit    int
	OutDir       string
	ExtraHeader  string
	Silent       bool
	ColorBlind   bool
}

type VulnerabilityMetadata struct {
	BaseURL    string
	InjectType string
	HeaderName string
}

var (
	InputFile    *string
	CollabServer *string
	Threads      *int
	RateLimit    *int
	OutDir       *string
	ExtraHeader  *string
	Silent       *bool
	ColorBlind   *bool

	PayloadsFile  = filepath.Join(os.Getenv("HOME"), ".config", "ressrf", "payloads.cfg")
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
	AltProtoRegex  = regexp.MustCompile(`169\.254\.169\.254|latest/meta-data|root:|127\.0\.0\.1|localhost|gopher://|dict://|file://`)
	QsReplaceRegex = regexp.MustCompile(`=([^?|&]*)`)
)

// EnsurePayloadsConfig initializes or appends default vectors safely on the host system
func EnsurePayloadsConfig(silent bool) error {
	configDir := filepath.Dir(PayloadsFile)

	// Create ~/.config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	if _, err := os.Stat(PayloadsFile); os.IsNotExist(err) {
		if !silent {
			fmt.Printf("[*] First-time initialization: Writing default payloads to %s\n", PayloadsFile)
		}
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
			fmt.Printf("[*] Syncing workspace: Appending %d new default payloads to %s\n", len(linesToAppend), PayloadsFile)
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

func ParseOptions() (*Options, error) {
	os.Args[0] = "ressrf"

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`ReSSRF - An advanced Out-of-Band and In-Band SSRF fuzzing scanner with dynamic request tracking.`)

	flagSet.CreateGroup("input", "Input Target Options",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "\tInput file containing target URLs (Required)"),
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
	)

	flagSet.CreateGroup("output", "Output Directories",
		flagSet.StringVarP(&options.OutDir, "outdir", "o", "output", "\tTarget folder to generate activity logs and vulnerabilities reports"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if options.InputFile == "" {
		return nil, fmt.Errorf("[!] RESSRF Error: Input target list file is required. Use -l <file>")
	}

	fileInfo, err := os.Stat(options.InputFile)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("[!] RESSRF Error: Specified input file '%s' does not exist", options.InputFile)
	}
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("[!] RESSRF Error: '%s' is a directory, expected a regular file", options.InputFile)
	}
	if fileInfo.Size() == 0 {
		return nil, fmt.Errorf("[!] RESSRF Error: Specified input file '%s' is empty", options.InputFile)
	}

	// Automatically run the sync configuration pipeline seamlessly
	if err := EnsurePayloadsConfig(options.Silent); err != nil {
		return nil, fmt.Errorf("[!] Config Setup Error: %v", err)
	}

	InputFile = &options.InputFile
	CollabServer = &options.CollabServer
	Threads = &options.Threads
	RateLimit = &options.RateLimit
	OutDir = &options.OutDir
	ExtraHeader = &options.ExtraHeader
	Silent = &options.Silent
	ColorBlind = &options.ColorBlind

	return options, nil
}
