package config

import (
	"flag"
	"fmt"
	"os"
)

type Options struct {
	Arg_t                string
	Arg_tf               string
	Arg_exclude_hosts    string
	Arg_r                string
	Arg_rc               int
	Arg_p                string
	Arg_jp               bool
	Arg_pc               int
	Arg_masscan_args     string
	Arg_nmap_args        string
	Arg_disable_nmap     bool
	Arg_nmap_concurrency int
	Arg_disable_nmap_test bool
	Arg_print_stats      bool
	Arg_prune_cache      int
	Arg_flush_cache      bool
	Arg_cache_file       string
	Arg_o                string
	Arg_ohp              string
	Arg_6                bool
	Arg_scope           string
}

func ParseOptions() *Options {
	opts := &Options{}

	flag.StringVar(&opts.Arg_t, "t", "", "domain/IP/CIDR to scan")
	flag.StringVar(&opts.Arg_tf, "tf", "", "file with domains/IPs/CIDRs to scan")
	flag.StringVar(&opts.Arg_exclude_hosts, "exclude-hosts", "", "hosts to exclude, IPs separated by a comma")
	flag.StringVar(&opts.Arg_r, "r", "", "resolvers to use for DNS resolution")
	flag.IntVar(&opts.Arg_rc, "rc", 16, "number of maximum concurrent domain resolutions")
	flag.StringVar(&opts.Arg_p, "p", "", "ports to scan, for example: 22,80,443 or 1-65535")
	flag.BoolVar(&opts.Arg_jp, "jp", false, "juicy ports, use internal port list")
	flag.IntVar(&opts.Arg_pc, "pc", -1, "scan for top N ports learned from previous runs, if 0 is specified, all ports will be scanned")
	flag.StringVar(&opts.Arg_masscan_args, "masscan-args", "--rate=1000", "masscan arguments")
	flag.StringVar(&opts.Arg_nmap_args, "nmap-args", "", "nmap arguments")
	flag.BoolVar(&opts.Arg_disable_nmap, "disable-nmap", false, "do not run nmap")
	flag.IntVar(&opts.Arg_nmap_concurrency, "nmap-concurrency", 4, "number of maximum concurrent nmap scans, default is 4")
	flag.BoolVar(&opts.Arg_disable_nmap_test, "disable-nmap-test", false, "do not test nmap arguments before running")
	flag.StringVar(&opts.Arg_scope, "s", "", "file containing scope definitions (CIDRs, IPs, domains)")
	flag.StringVar(&opts.Arg_scope, "scope", "", "file containing scope definitions (CIDRs, IPs, domains)")

	flag.BoolVar(&opts.Arg_print_stats, "print-stats", false, "show statistics from cache and exit")
	flag.IntVar(&opts.Arg_prune_cache, "prune-cache", -1, "remove from cache ports with less than N occurrences, 2 is recommended")
	flag.BoolVar(&opts.Arg_flush_cache, "flush-cache", false, "forget everything (removes cache file)")
	flag.StringVar(&opts.Arg_cache_file, "cache-file", "", "custom cache file path (default: ~/.massmap/port_cache.json)")

	flag.StringVar(&opts.Arg_o, "o", "", "save complete results to output file")
	flag.StringVar(&opts.Arg_ohp, "ohp", "", "save only host:port to output file")
	flag.BoolVar(&opts.Arg_6, "6", false, "enable IPv6 targets, note that masscan does not support IPv6")

	flag.Usage = func() {
		flagSet := flag.CommandLine
		template := " %-20s %s\n"
		fmt.Printf("Usage of %s:\n\n", os.Args[0])

		fmt.Println("Target options:")
		fmt.Printf(template, "-t", flagSet.Lookup("t").Usage)
		fmt.Printf(template, "-tf", flagSet.Lookup("tf").Usage)
		fmt.Printf(template, "-exclude-hosts", flagSet.Lookup("exclude-hosts").Usage)
		fmt.Printf(template, "-s", flagSet.Lookup("s").Usage)
		fmt.Printf(template, "-scope", flagSet.Lookup("scope").Usage)
		fmt.Println()
		fmt.Println("Port options:")
		fmt.Printf(template, "-p", flagSet.Lookup("p").Usage)
		fmt.Printf(template, "-jp", flagSet.Lookup("jp").Usage)
		fmt.Printf(template, "-pc", flagSet.Lookup("pc").Usage)
		fmt.Println()
		fmt.Println("DNS options:")
		fmt.Printf(template, "-r", flagSet.Lookup("r").Usage)
		fmt.Printf(template, "-rc", flagSet.Lookup("rc").Usage)
		fmt.Println()
		fmt.Println("Masscan options:")
		fmt.Printf(template, "-masscan-args", flagSet.Lookup("masscan-args").Usage)
		fmt.Println()
		fmt.Println("Nmap options:")
		fmt.Printf(template, "-nmap-args", flagSet.Lookup("nmap-args").Usage)
		fmt.Printf(template, "-disable-nmap", flagSet.Lookup("disable-nmap").Usage)
		fmt.Printf(template, "-nmap-concurrency", flagSet.Lookup("nmap-concurrency").Usage)
		fmt.Printf(template, "-disable-nmap-test", flagSet.Lookup("disable-nmap-test").Usage)
		fmt.Println()
		fmt.Println("Port cache:")
		fmt.Printf(template, "-print-stats", flagSet.Lookup("print-stats").Usage)
		fmt.Printf(template, "-prune-cache", flagSet.Lookup("prune-cache").Usage)
		fmt.Printf(template, "-flush-cache", flagSet.Lookup("flush-cache").Usage)
		fmt.Printf(template, "-cache-file", flagSet.Lookup("cache-file").Usage)
		fmt.Println()
		fmt.Println("Output options:")
		fmt.Printf(template, "-o", flagSet.Lookup("o").Usage)
		fmt.Printf(template, "-ohp", flagSet.Lookup("ohp").Usage)
		fmt.Println()
		fmt.Println("IPv6:")
		fmt.Printf(template, "-6", flagSet.Lookup("6").Usage)
		fmt.Println()
		fmt.Println(" Examples:")
		fmt.Println("  Scan for all ports with packet rate of 10000 and 6 concurrent nmap processes, save full and host:port output:")
		fmt.Println("     massmap --masscan-args='--rate 10000' --nmap-concurrency 6 --nmap-args='-sV -T4' -p 0-65535 -t x.x.x.x/xx -o output.json -ohp host_port.txt")
		fmt.Println("  Scan only for the most probable ports based on the previous runs and use custom DNS resolvers:")
		fmt.Println("     massmap --masscan-args='--rate 10000' --nmap-concurrency 6 --nmap-args='-sV -T4' -pc 0 -r resolvers.txt -t x.x.x.x/xx")
		fmt.Println("  Show cache statistics:")
		fmt.Println("     massmap -print-stats")
		fmt.Println("  Remove ports from cache that were discovered only 2 times and less:")
		fmt.Println("     massmap -prune-cache 2")
		fmt.Println()
	}

	flag.Parse()

	return opts
}
