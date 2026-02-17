package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/nullt3r/massmap/pkg/utils"
)

type Masscan struct {
	Ports         string
	TargetsPath   string
	UserArguments string
	Findings      *[]Finding
	Mutex         *sync.RWMutex
	Logger        *log.Logger
	BufferSize    int // Size of the buffer for reading output
}

// NewMasscan creates a new Masscan instance with default configuration
func NewMasscan(ports, targetsPath string, findings *[]Finding, mutex *sync.RWMutex, logger *log.Logger) *Masscan {
	return &Masscan{
		Ports:       ports,
		TargetsPath: targetsPath,
		Findings:    findings,
		Mutex:       mutex,
		Logger:      logger,
		BufferSize:  4096, // Default 4KB buffer
	}
}

func TestMasscanArgs(userArgs string) (io.Reader, error) {
	testMasscanArgs := "masscan --wait=0 -p 62734 127.0.0.1 " + userArgs
	_, stderr, err := utils.RunCommand(false, strings.Split(testMasscanArgs, " ")...)
	return stderr, err
}

// readDelimitedLines reads from r and calls handle for each complete "line" terminated by '\n' or '\r'.
// This is important for masscan output which often uses '\r' for progress updates.
// It returns when the reader is closed or returns an error.
func readDelimitedLines(r io.Reader, bufSize int, handle func(string)) error {
	tmp := make([]byte, bufSize)
	var pending []byte

	for {
		n, err := r.Read(tmp)
		if n > 0 {
			pending = append(pending, tmp[:n]...)
			for {
				idx := bytes.IndexAny(pending, "\r\n")
				if idx == -1 {
					break
				}

				line := string(pending[:idx])
				next := idx + 1
				// Handle CRLF
				if pending[idx] == '\r' && next < len(pending) && pending[next] == '\n' {
					next++
				}
				pending = pending[next:]
				handle(line)
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if len(pending) > 0 {
		handle(string(pending))
	}
	return nil
}

// Run executes the masscan command with proper context handling and concurrency control
func (i *Masscan) Run(ctx context.Context) error {
	if i.BufferSize == 0 {
		i.BufferSize = 4096 // Fallback buffer size if not set
	}

	logger := i.Logger
	args := []string{"masscan", "-p", i.Ports, "-iL", i.TargetsPath}

	if len(i.UserArguments) != 0 {
		args = append(args, strings.Split(i.UserArguments, " ")...)
	}

	logger.Printf("consider increasing or decreasing the masscan's rate")
	logger.Printf("scan started")

	// Use exec.Command (not CommandContext) so we fully control the process
	// lifecycle, including killing the entire process group on shutdown.
	command := exec.Command(args[0], args[1:]...)
	setProcGroup(command)

	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := command.Start(); err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}

	errChan := make(chan error, 2)
	var stderrOutput strings.Builder
	var outputMu sync.Mutex

	// Process stdout in a goroutine (port discoveries).
	go func() {
		err := readDelimitedLines(stdout, i.BufferSize, func(line string) {
			if strings.HasPrefix(line, "Discovered open port ") {
				outputMu.Lock()
				fmt.Print("\r\033[K")
				if err := i.processDiscoveredPort(line); err != nil {
					logger.Printf("error processing port: %v", err)
				}
				outputMu.Unlock()
			}
		})
		if err != nil {
			errChan <- fmt.Errorf("error reading stdout: %v", err)
		}
	}()

	// Process stderr in a goroutine (progress + diagnostics).
	go func() {
		err := readDelimitedLines(stderr, i.BufferSize, func(line string) {
			if line == "" {
				return
			}
			stderrOutput.WriteString(line)
			stderrOutput.WriteString("\n")
			if strings.HasPrefix(line, "rate: ") {
				outputMu.Lock()
				fmt.Printf("\r%s", line)
				outputMu.Unlock()
			}
		})
		if err != nil {
			errChan <- fmt.Errorf("error reading stderr: %v", err)
		}
	}()

	// Wait for command completion or first stream error.
	waitErr := make(chan error, 1)
	go func() { waitErr <- command.Wait() }()

	select {
	case <-ctx.Done():
		// Close pipes to unblock reader goroutines, then kill the entire process group.
		_ = stdout.Close()
		_ = stderr.Close()
		killProcessGroup(command)
		select {
		case <-waitErr:
		case <-time.After(3 * time.Second):
		}
		return ctx.Err()
	case err := <-errChan:
		killProcessGroup(command)
		select {
		case <-waitErr:
		case <-time.After(3 * time.Second):
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	case err := <-waitErr:
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			cmdStr := strings.Join(args, " ")
			errStr := strings.TrimSpace(stderrOutput.String())
			if errStr == "" {
				errStr = "no error output"
			}
			return fmt.Errorf("command failed: '%s'\nOutput: %s\nError: %v", cmdStr, errStr, err)
		}
	}

	fmt.Println()
	return nil
}

// processDiscoveredPort handles the processing of discovered ports with proper synchronization
func (i *Masscan) processDiscoveredPort(output string) error {
	parts := strings.Split(output, " ")
	if len(parts) < 6 {
		return fmt.Errorf("unexpected output format: %s", output)
	}

	host := parts[5]
	portParts := strings.Split(parts[3], "/")
	if len(portParts) == 0 {
		return fmt.Errorf("invalid port format: %s", parts[3])
	}
	port := portParts[0]

	if utils.IsIPv6(host) {
		i.Logger.Printf("[%s]:%s", host, port)
	} else {
		i.Logger.Printf("%s:%s", host, port)
	}

	i.Mutex.Lock()
	defer i.Mutex.Unlock()

	// Find existing host or create new entry
	var hostEntry *Finding
	for n := range *i.Findings {
		if (*i.Findings)[n].Host == host {
			hostEntry = &(*i.Findings)[n]
			break
		}
	}

	if hostEntry == nil {
		*i.Findings = append(*i.Findings, Finding{
			Host:  host,
			Ports: []string{port},
		})
	} else {
		// Check for duplicate ports
		for _, existingPort := range hostEntry.Ports {
			if existingPort == port {
				return nil // Port already exists
			}
		}
		hostEntry.Ports = append(hostEntry.Ports, port)
	}

	return nil
}
