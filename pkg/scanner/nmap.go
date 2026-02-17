package scanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/nullt3r/massmap/pkg/color"
	"github.com/nullt3r/massmap/pkg/nmapxml"
	"github.com/nullt3r/massmap/pkg/utils"
)

type Nmap struct {
	UserArguments string
	Findings      *[]Finding
	Concurrency   int
	Mutex         *sync.RWMutex
	Logger        *log.Logger
}

func TestNmapArgs(userArgs string) (io.Reader, error) {
	testNmapArgs := "nmap 127.0.0.1 -p 65534 -Pn -n " + userArgs

	_, stderr, err := utils.RunCommand(false, strings.Split(testNmapArgs, " ")...)

	return stderr, err
}

func (i Nmap) Run(ctx context.Context) {
	logger := i.Logger
	concurrency := i.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	guard := make(chan struct{}, concurrency)

	var wg sync.WaitGroup

	args := []string{"nmap", "--noninteractive", "-Pn", "-n", "-oX", "-"}

	if len(i.UserArguments) != 0 {
		args = append(args, strings.Split(i.UserArguments, " ")...)
	}

	logger.Printf("scan started")

	for x := range *i.Findings {
		if ctx.Err() != nil {
			break
		}

		target := &(*i.Findings)[x]

		if len(target.Ports) == 0 {
			continue
		}

		// Build a per-target argument slice and pass it into the goroutine to avoid closure capture bugs.
		argsCopy := make([]string, len(args))
		copy(argsCopy, args)
		finalArgs := make([]string, 0, len(argsCopy)+6)
		finalArgs = append(finalArgs, argsCopy...)
		if utils.IsIPv6(target.Host) {
			finalArgs = append(finalArgs, "-6")
		}
		finalArgs = append(finalArgs, "-p", strings.Join(target.Ports, ","), target.Host)

		// Acquire concurrency slot, respecting context cancellation.
		select {
		case guard <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)

		go func(target *Finding, finalArgs []string) {
			defer wg.Done()
			defer func() { <-guard }()

			command := exec.CommandContext(ctx, finalArgs[0], finalArgs[1:]...)
			setProcGroup(command)
			command.Cancel = func() error {
				return cancelProcessGroup(command)
			}
			command.WaitDelay = 3 * time.Second

			stdout, err := command.StdoutPipe()
			if err != nil {
				logger.Printf("failed to create stdout pipe: %v", err)
				return
			}

			if err := command.Start(); err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Printf("failed to start nmap: %v", err)
				return
			}

			data, err := io.ReadAll(stdout)

			if err != nil {
				if ctx.Err() != nil {
					_ = command.Wait()
					return
				}
				logger.Printf("failed reading nmap output: %v", err)
				_ = command.Wait()
				return
			}

			if err := command.Wait(); err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Printf("%s", err)
			}

			nmapOutput, err := nmapxml.Parse(&data)
			if err != nil {
				logger.Printf("failed to parse nmap output: %v", err)
				return
			}

			i.Mutex.Lock()
			target.Details = nmapOutput
			i.Mutex.Unlock()

			for _, host := range nmapOutput.Hosts {
				if len(host.Ports) != len(target.Ports) {
					logger.Printf("host %s had previously %d open ports, but nmap found %d", target.Host, len(target.Ports), len(host.Ports))
				}

				message := ""

				message += target.Host

				if len(target.Domains) != 0 {
					message += " (" + strings.Join(target.Domains, ", ") + ")"
				}

				message += "\n"

				for _, port := range host.Ports {
					if port.State.State == "open" {
						message += fmt.Sprintf(" %sopen%s", color.SetColor().Green, color.SetColor().Reset)
					}

					if port.State.State == "filtered" {
						message += fmt.Sprintf(" %sfiltered%s", color.SetColor().Yellow, color.SetColor().Reset)
					}

					if port.State.State == "closed" {
						message += fmt.Sprintf(" %sclosed%s", color.SetColor().Red, color.SetColor().Reset)
					}

					message += fmt.Sprintf(" %s (%s) %s[%s] [%s] [%s]%s\n",
						port.ID,
						port.Service.Name,
						color.SetColor().Green,
						port.Service.Product,
						port.Service.Version,
						port.Service.CPE,
						color.SetColor().Reset,
					)

					if len(port.Script) != 0 {
						for _, script := range port.Script {
							var scriptOutput string
							if len(script.Output) > 0 && script.Output[0] == '\n' {
								scriptOutput = script.Output[1:]
							} else {
								scriptOutput = script.Output
							}
							message += fmt.Sprintf("  - %s\n", script.ID)
							for _, line := range strings.Split(scriptOutput, "\n") {
								message += fmt.Sprintf("     %s%s%s\n", color.SetColor().Yellow, line, color.SetColor().Reset)
							}
						}
					}

				}
				logger.Print(message)
			}

		}(target, finalArgs)
	}

	wg.Wait()

}
