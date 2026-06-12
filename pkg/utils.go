package pkg

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/interactsh/pkg/client"
)

// Global instance pointers for cleaner multi-file state reference
var (
	ClientInstance *client.Client
	SessionDomain  string
)

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

func AppendLine(path, line string) {
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

// StartInteractsh client initializes the real-time background tracker module cleanly in memory
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

func regexpHost(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "http://", ""), "https://", "")
}

func RunPhase(name string, jobs chan<- func(), wg *sync.WaitGroup, fn func()) {
	fmt.Printf("[*] %s\n", name)
	fn()
}
