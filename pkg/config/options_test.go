package config

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func parseWithArgs(t *testing.T, args ...string) *Options {
	t.Helper()

	originalArgs := os.Args
	originalFlagSet := flag.CommandLine
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlagSet
	})

	os.Args = append([]string{"massmap"}, args...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)

	return ParseOptions()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = w
	defer func() {
		os.Stdout = originalStdout
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close write end: %v", err)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}

	return string(out)
}

func TestParseOptionsDefaults(t *testing.T) {
	opts := parseWithArgs(t)

	if opts.Arg_rc != 16 {
		t.Errorf("Arg_rc = %d, want 16", opts.Arg_rc)
	}
	if opts.Arg_masscan_args != "--rate=1000" {
		t.Errorf("Arg_masscan_args = %q, want %q", opts.Arg_masscan_args, "--rate=1000")
	}
	if opts.Arg_nmap_concurrency != 4 {
		t.Errorf("Arg_nmap_concurrency = %d, want 4", opts.Arg_nmap_concurrency)
	}
	if opts.Arg_pc != -1 {
		t.Errorf("Arg_pc = %d, want -1", opts.Arg_pc)
	}
	if opts.Arg_disable_nmap {
		t.Errorf("Arg_disable_nmap = %v, want false", opts.Arg_disable_nmap)
	}
	if opts.Arg_6 {
		t.Errorf("Arg_6 = %v, want false", opts.Arg_6)
	}
}

func TestParseOptionsCustomValues(t *testing.T) {
	opts := parseWithArgs(
		t,
		"-t", "example.com",
		"-tf", "targets.txt",
		"-exclude-hosts", "1.1.1.1,2.2.2.2",
		"-r", "resolvers.txt",
		"-rc", "32",
		"-p", "80,443",
		"-jp",
		"-pc", "10",
		"-masscan-args", "--rate=5000",
		"-nmap-args", "-sV -T4",
		"-disable-nmap",
		"-nmap-concurrency", "8",
		"-disable-nmap-test",
		"-print-stats",
		"-prune-cache", "2",
		"-flush-cache",
		"-cache-file", "cache.json",
		"-o", "full.json",
		"-ohp", "host_port.txt",
		"-6",
		"-scope", "scope.txt",
	)

	if opts.Arg_t != "example.com" {
		t.Errorf("Arg_t = %q, want %q", opts.Arg_t, "example.com")
	}
	if opts.Arg_tf != "targets.txt" {
		t.Errorf("Arg_tf = %q, want %q", opts.Arg_tf, "targets.txt")
	}
	if opts.Arg_exclude_hosts != "1.1.1.1,2.2.2.2" {
		t.Errorf("Arg_exclude_hosts = %q, want %q", opts.Arg_exclude_hosts, "1.1.1.1,2.2.2.2")
	}
	if opts.Arg_r != "resolvers.txt" {
		t.Errorf("Arg_r = %q, want %q", opts.Arg_r, "resolvers.txt")
	}
	if opts.Arg_rc != 32 {
		t.Errorf("Arg_rc = %d, want 32", opts.Arg_rc)
	}
	if opts.Arg_p != "80,443" {
		t.Errorf("Arg_p = %q, want %q", opts.Arg_p, "80,443")
	}
	if !opts.Arg_jp {
		t.Errorf("Arg_jp = %v, want true", opts.Arg_jp)
	}
	if opts.Arg_pc != 10 {
		t.Errorf("Arg_pc = %d, want 10", opts.Arg_pc)
	}
	if opts.Arg_masscan_args != "--rate=5000" {
		t.Errorf("Arg_masscan_args = %q, want %q", opts.Arg_masscan_args, "--rate=5000")
	}
	if opts.Arg_nmap_args != "-sV -T4" {
		t.Errorf("Arg_nmap_args = %q, want %q", opts.Arg_nmap_args, "-sV -T4")
	}
	if !opts.Arg_disable_nmap {
		t.Errorf("Arg_disable_nmap = %v, want true", opts.Arg_disable_nmap)
	}
	if opts.Arg_nmap_concurrency != 8 {
		t.Errorf("Arg_nmap_concurrency = %d, want 8", opts.Arg_nmap_concurrency)
	}
	if !opts.Arg_disable_nmap_test {
		t.Errorf("Arg_disable_nmap_test = %v, want true", opts.Arg_disable_nmap_test)
	}
	if !opts.Arg_print_stats {
		t.Errorf("Arg_print_stats = %v, want true", opts.Arg_print_stats)
	}
	if opts.Arg_prune_cache != 2 {
		t.Errorf("Arg_prune_cache = %d, want 2", opts.Arg_prune_cache)
	}
	if !opts.Arg_flush_cache {
		t.Errorf("Arg_flush_cache = %v, want true", opts.Arg_flush_cache)
	}
	if opts.Arg_cache_file != "cache.json" {
		t.Errorf("Arg_cache_file = %q, want %q", opts.Arg_cache_file, "cache.json")
	}
	if opts.Arg_o != "full.json" {
		t.Errorf("Arg_o = %q, want %q", opts.Arg_o, "full.json")
	}
	if opts.Arg_ohp != "host_port.txt" {
		t.Errorf("Arg_ohp = %q, want %q", opts.Arg_ohp, "host_port.txt")
	}
	if !opts.Arg_6 {
		t.Errorf("Arg_6 = %v, want true", opts.Arg_6)
	}
	if opts.Arg_scope != "scope.txt" {
		t.Errorf("Arg_scope = %q, want %q", opts.Arg_scope, "scope.txt")
	}
}

func TestParseOptionsUsageContainsSupportedFlags(t *testing.T) {
	parseWithArgs(t)

	usage := captureStdout(t, func() {
		flag.Usage()
	})

	expectedSnippets := []string{
		"Target options:",
		"Port options:",
		"DNS options:",
		"Masscan options:",
		"Nmap options:",
		"Port cache:",
		"Output options:",
		"IPv6:",
		"-t",
		"-tf",
		"-exclude-hosts",
		"-s",
		"-scope",
		"-p",
		"-jp",
		"-pc",
		"-r",
		"-rc",
		"-masscan-args",
		"-nmap-args",
		"-disable-nmap",
		"-nmap-concurrency",
		"-disable-nmap-test",
		"-print-stats",
		"-prune-cache",
		"-flush-cache",
		"-cache-file",
		"-o",
		"-ohp",
		"-6",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(usage, snippet) {
			t.Errorf("usage does not contain %q", snippet)
		}
	}
}
