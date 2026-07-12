package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "syscall"

    "hellcat/config"
    "hellcat/parser"
    "hellcat/stressor"
)

const (
    hardLimit       = 100_000
    scannerInitSize = 64 * 1024
    scannerMaxSize  = 1024 * 1024

    tempConfigPattern = config.TempFilePrefix + "*"
)

func main() {
    cleanupTempFiles()

    vlessURL := flag.String("url", "", "Proxy link (vless/vmess/trojan/ss/hy2/tuic)")
    listFile := flag.String("list", "", "File with links")
    maxProxies := flag.Int("max-proxies", 0, "Max proxies to load from file (0=default limit 100k, prevents OOM)")
    threadCount := flag.Int("threads", 200, "Threads per proxy")
    duration := flag.Int("duration", 0, "Duration in seconds (0=infinite)")
    numXray := flag.Int("instances", 20, "Number of xray-core processes")
    insane := flag.Bool("insane", false, "Insane mode (2x workers, burst=6)")
    stealth := flag.Bool("stealth", false, "Use pseudo-load instead of heavy downloads")
    customTarget := flag.String("target", "", "Custom download URL (overrides built-in list)")
    fakelogin := flag.Bool("fakelogin", false, "Rotate UUID/Password every 1000 requests")
    cpuTarget := flag.Int("cpu", 0, "CPU usage target %% (0=auto: 70 normal, 85 insane)")
    maxInFlight := flag.Int("inflight", 0, "Max concurrent requests (0=default 10000)")
    flag.Parse()

    switch {
    case *maxProxies < 0:
        log.Fatalf("[!] --max-proxies cannot be negative")
    case *maxProxies == 0:
        log.Printf("[hellcat] ℹ️ No --max-proxies set. Using default limit: %d", hardLimit)
        *maxProxies = hardLimit
    case *maxProxies > hardLimit:
        log.Printf("[!] Capping --max-proxies from %d to %d to prevent OOM.", *maxProxies, hardLimit)
        *maxProxies = hardLimit
    }

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    go setupSignalHandler(ctx, cancel)

    if *vlessURL != "" && *listFile != "" {
        log.Println("[!] Both --url and --list provided. --list will be ignored.")
    }

    configs, err := parseConfigs(ctx, *vlessURL, *listFile, *maxProxies)
    if err != nil {
        log.Fatalf("[!] %v", err)
    }
    if len(configs) == 0 {
        log.Fatal("No valid proxy links found. Specify --url or --list.")
    }

    log.Printf("[hellcat] ✅ Loaded %d proxy config(s)", len(configs))

    stressor.Run(
        ctx,
        configs,
        *threadCount,
        *duration,
        *numXray,
        *insane,
        *stealth,
        *customTarget,
        *fakelogin,
        *cpuTarget,
        *maxInFlight,
    )
}

func cleanupTempFiles() {
    matches, err := filepath.Glob(tempConfigPattern)
    if err != nil {
        log.Printf("[!] Error searching temp files: %v", err)
        return
    }
    for _, f := range matches {
        if err := os.Remove(f); err != nil {
            log.Printf("[!] Cannot remove temp file %s: %v", f, err)
        }
    }
}

func setupSignalHandler(ctx context.Context, cancel context.CancelFunc) {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    select {
    case sig := <-sigCh:
        log.Printf("[hellcat] ⛔ Received signal: %v. Shutting down gracefully...", sig)
        cancel()
    case <-ctx.Done():
    }
}

func parseConfigs(ctx context.Context, rawURL, listFile string, maxProxies int) ([]*parser.OutboundConfig, error) {
    if rawURL != "" {
        cfg, err := parser.Parse(rawURL)
        if err != nil {
            return nil, fmt.Errorf("parse error: %w", err)
        }
        return []*parser.OutboundConfig{cfg}, nil
    }

    if listFile == "" {
        return nil, nil
    }

    f, err := os.Open(listFile)
    if err != nil {
        return nil, fmt.Errorf("failed to open file %q: %w", listFile, err)
    }
    defer func() {
        if err := f.Close(); err != nil {
            log.Printf("[!] Error closing list file: %v", err)
        }
    }()

    var configs []*parser.OutboundConfig
    scanner := bufio.NewScanner(f)
    scanner.Buffer(make([]byte, 0, scannerInitSize), scannerMaxSize)

    count := 0
    for scanner.Scan() {
        if ctx.Err() != nil {
            log.Println("[hellcat] ⚠️ Proxy loading interrupted by signal.")
            return configs, nil
        }

        raw := strings.TrimSpace(scanner.Text())
        if raw == "" || strings.HasPrefix(raw, "#") {
            continue
        }

        cfg, err := parser.Parse(raw)
        if err != nil {
            log.Printf("[!] Parse error (%s): %v", truncateRunes(raw, 50), err)
            continue
        }

        configs = append(configs, cfg)
        count++

        if count >= maxProxies {
            log.Printf("[hellcat] ℹ️ Reached --max-proxies limit (%d). Stopping read.", maxProxies)
            break
        }
    }

    if err := scanner.Err(); err != nil {
        log.Printf("[!] Error reading list file: %v", err)
    }

    return configs, nil
}

func truncateRunes(s string, maxRunes int) string {
    count := 0
    for i := range s {
        if count >= maxRunes {
            return s[:i] + "..."
        }
        count++
    }
    return s
}
