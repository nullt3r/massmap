package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nullt3r/massmap/pkg/cache"
	"github.com/nullt3r/massmap/pkg/color"
	"github.com/nullt3r/massmap/pkg/config"
	"github.com/nullt3r/massmap/pkg/scanner"
	"github.com/nullt3r/massmap/pkg/utils"
)

// Version will be set at build time using -ldflags
var Version = "dev"

func main() {
	printBanner(Version)

	findingsManager := scanner.NewFindingsManager()
	var untrustedTargets, targets, excludedHosts []string
	var ports string

	loggerMain := log.New(os.Stdout, fmt.Sprintf("%s[main]%s ", color.SetColor().Cyan, color.SetColor().Reset), 0)
	loggerMasscan := log.New(os.Stdout, fmt.Sprintf("%s[masscan]%s ", color.SetColor().Cyan, color.SetColor().Reset), 0)
	
	arguments := config.ParseOptions()
	cacheFile := ".massmap_port_cache.json"

	if len(arguments.Arg_cache_file) != 0 {
		cacheFile = arguments.Arg_cache_file
	}

	portCache, err := cache.Initialize(cacheFile, findingsManager.Storage)
	if err != nil {
		loggerMain.Fatal(err)
	}

	if arguments.Arg_print_stats {
		err := portCache.PrintStats()
		if err != nil {
			loggerMain.Fatalln(err)
		}
		os.Exit(0)
	}

	if arguments.Arg_flush_cache {
		result, err := utils.YesNoPrompt("Are you sure you want to flush the cache?", true)
		if err != nil {
			loggerMain.Fatalf("Error reading input: %v", err)
		}
		if result {
			loggerMain.Printf("removing cache")
			err := portCache.FlushCache()
			if err != nil {
				loggerMain.Fatalln(err)
			}
			loggerMain.Printf("success")
		}
		os.Exit(0)
	}

	if arguments.Arg_prune_cache > 0 {
		loggerMain.Printf("pruning port cache with level of %d", arguments.Arg_prune_cache)
		removed, err := portCache.PruneCache(arguments.Arg_prune_cache)
		if err != nil {
			loggerMain.Fatalf("error pruning port cache: %s", err)
		}
		loggerMain.Printf("success, removed %d ports from cache", removed)
		os.Exit(0)
	}

	if len(arguments.Arg_p) == 0 && !arguments.Arg_jp && arguments.Arg_pc == -1 {
		loggerMain.Fatalf("error, argument -p, -jp or -pc is not provided")
	}

	if len(arguments.Arg_t) == 0 && len(arguments.Arg_tf) == 0 {
		loggerMain.Fatalf("error, argument -t or -tf is required")
	}

	if len(arguments.Arg_tf) != 0 {
		tf, err := utils.ReadFile(arguments.Arg_tf)
		untrustedTargets = append(untrustedTargets, tf...)

		if err != nil {
			loggerMain.Fatalf("error while loading targets from file: %s", err)
		}
	} else {
		untrustedTargets = append(untrustedTargets, arguments.Arg_t)
	}

	if len(arguments.Arg_exclude_hosts) != 0 {
		excludedHosts = strings.Split(arguments.Arg_exclude_hosts, ",")
	}

	loggerMain.Printf("loading targets and resolving domains (this may take a while)")

	loader := scanner.TargetLoader{
		UserTargets:    &untrustedTargets,
		FinalTargets:   &targets,
		ExcludedHosts:  &excludedHosts,
		Findings:       findingsManager.Storage,
		IPv6Enabled:    arguments.Arg_6,
		DNSConcurrency: arguments.Arg_rc,
		Logger:         loggerMain,
		ScopeFile:      arguments.Arg_scope,
	}

	if len(arguments.Arg_r) != 0 {
		loader.ResolversFile = arguments.Arg_r
	}

	loader.Load()

	if len(targets) == 0 {
		loggerMain.Fatalf("no hosts to scan, exiting")
	}

	if arguments.Arg_jp {
		ports = utils.JuicyPorts()
	} else if arguments.Arg_pc != -1 {
		loggerMain.Println("using learned port numbers from previous runs, check '-print-stats' for more info")
		if arguments.Arg_pc == 0 {
			p, err := portCache.GetAll()
			if err != nil {
				loggerMain.Fatalln(err)
			}
			if len(p) == 0 {
				loggerMain.Fatalf("port cache is empty, please specify ports using -p flag or use -jp for juicy ports")
			}
			ports = strings.Join(p, ",")
		} else if arguments.Arg_pc > 0 {
			p, err := portCache.GetTop(arguments.Arg_pc)
			if err != nil {
				loggerMain.Fatalln(err)
			}
			if len(p) == 0 {
				loggerMain.Fatalf("port cache is empty, please specify ports using -p flag or use -jp for juicy ports")
			}
			ports = strings.Join(p, ",")
		}
	} else {
		ports = arguments.Arg_p
	}

	targetsFile, err := utils.WriteTargetsToFile(&targets)
	if err != nil {
		loggerMain.Fatalf("error: %s", err)
	}
	defer os.Remove(targetsFile)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		// First signal: cancel and let defers run.
		// Second signal: force exit.
		sig := <-sigChan
		_ = sig
		loggerMain.Println("received shutdown signal, cleaning up...")
		cancel()

		select {
		case <-sigChan:
			loggerMain.Println("received second shutdown signal, forcing exit")
			os.Exit(1)
		case <-time.After(5 * time.Second):
			// If something is stuck after a grace period, force exit to match user expectations.
			loggerMain.Println("shutdown timed out, forcing exit")
			os.Exit(1)
		}
	}()

	start := time.Now()

	masscan := scanner.Masscan{
		UserArguments: arguments.Arg_masscan_args,
		Ports:         ports,
		TargetsPath:   targetsFile,
		Findings:      findingsManager.Storage,
		Mutex:         findingsManager.Mutex,
		Logger:        loggerMasscan,
	}
	
	if err := masscan.Run(ctx); err != nil {
		if err == context.Canceled {
			loggerMain.Println("scan was cancelled")
			return
		}
		loggerMain.Printf("scan failed: %v", err)
		return
	}

	// We don't want program to learn when using data from cache, it would be in feedback loop
	if arguments.Arg_pc == -1 {
		err := portCache.WriteCache()
		if err != nil {
			loggerMain.Println(err)
		}
	}

	if len(arguments.Arg_ohp) != 0 {
		loggerMain.Printf("saving 'host:port' output to '%s'", arguments.Arg_ohp)
		if err := findingsManager.SaveHostPortToFile(arguments.Arg_ohp); err != nil {
			loggerMain.Fatal(err)
		}
	}

	if !arguments.Arg_disable_nmap {
		loggerNmap := log.New(os.Stdout, fmt.Sprintf("%s[nmap]%s ", color.SetColor().Cyan, color.SetColor().Reset), 0)
		
		if !arguments.Arg_disable_nmap_test {
			stderr, err := scanner.TestNmapArgs(arguments.Arg_nmap_args)
			if err != nil {
				loggerMain.Fatalf("there was an error when validating nmap command: %s", stderr)
			}
		}

		nmap := scanner.Nmap{
			UserArguments: arguments.Arg_nmap_args,
			Findings:      findingsManager.Storage,
			Concurrency:   arguments.Arg_nmap_concurrency,
			Mutex:         findingsManager.Mutex,
			Logger:        loggerNmap,
		}
		nmap.Run(ctx)
	}

	if len(arguments.Arg_o) != 0 {
		err := findingsManager.SaveEverythingToFile(arguments.Arg_o)
		if err != nil {
			loggerMain.Fatal(err)
		}
	}

	elapsed := time.Since(start)
	loggerMain.Printf("scan finished in %s", elapsed)
}

func printBanner(version string) {
	fmt.Printf(`                    
  _____ ___ ___ ___ _____ ___ ___ 
 |     | .'|_ -|_ -|     | .'| . |
 |_|_|_|__,|___|___|_|_|_|__,|  _|
                             |_|
  author: @nullt3r build: %s
  https://github.com/nullt3r/massmap

`, version)
}
