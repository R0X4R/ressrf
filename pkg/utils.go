package pkg

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/interactsh/pkg/client"
)

// ClientInstance holds the active Interactsh client session, shared across packages.
var ClientInstance *client.Client

// SessionDomain stores the interaction domain returned by the Interactsh client, used as the
// callback target for out-of-band SSRF payloads.
var SessionDomain string

// ReadLines reads a file line by line, trimming whitespace and skipping blank lines and
// comment lines (those starting with "#"). Returns the non-empty lines or an error if the
// file cannot be opened.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

// AppendLine appends a single line of text to the file at the given path, creating the file
// if it does not already exist. Errors during open or write are silently discarded.
func AppendLine(path, line string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

// StartInteractsh creates a new Interactsh client using the ProjectDiscovery service and
// returns the generated collaboration domain. The global ClientInstance is set so that the
// caller can later close the session. Returns the raw domain string (protocol prefix stripped)
// or an error if the client cannot be initialized.
func StartInteractsh() (string, error) {
	var err error

	// Create the tracking profile using ProjectDiscovery defaults
	ClientInstance, err = client.New(&client.Options{
		ServerURL: "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
		CorrelationIdLength: 20,
	})
	if err != nil {
		return "", fmt.Errorf("failed to establish client session: %w", err)
	}

	// Generate and isolate the base tracking domain string
	rawURL := ClientInstance.URL()
	SessionDomain = regexpHost(rawURL)

	return SessionDomain, nil
}

// regexpHost strips "http://" and "https://" scheme prefixes from a URL string, returning
// the bare host (or host:port).
func regexpHost(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "http://", ""), "https://", "")
}

// RunPhase prints the phase name and then executes the provided function. It does not
// interact with the jobs channel or WaitGroup directly; those are managed by the caller
// inside fn.
func RunPhase(name string, jobs chan<- func(), wg *sync.WaitGroup, fn func()) {
	fmt.Printf("[INFO] %s\n", name)
	fn()
}
