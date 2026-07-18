package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"

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
    proxiesFile := flag.String("proxies", "", "File with upstream proxies (socks5://, http://, host:port) to chain before vless outbound")
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

    var validProxies []config.ProxyEntry
    if *proxiesFile != "" {
        rawProxies, err := config.LoadProxyList(*proxiesFile)
        if err != nil {
            log.Fatalf("[!] %v", err)
        }
        log.Printf("[hellcat] 🛡️  Loaded %d proxies from file. Checking them (timeout 3s)...", len(rawProxies))
        
        validProxies = checkProxiesConcurrently(rawProxies)
        if len(validProxies) == 0 {
            log.Fatal("[!] No working proxies found. Aborting.")
        }
        log.Printf("[hellcat] ✅ %d proxies are alive and ready for chaining.", len(validProxies))
    }

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
        validProxies,
    )
}

// checkProxiesConcurrently проверяет прокси пачками по 100 штук
func checkProxiesConcurrently(proxies []config.ProxyEntry) []config.ProxyEntry {
    var valid []config.ProxyEntry
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    sem := make(chan struct{}, 100) // Ограничиваем до 100 одновременных проверок
    total := len(proxies)
    checked := 0

    for _, p := range proxies {
        wg.Add(1)
        go func(proxy config.ProxyEntry) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()

            if checkProxy(proxy) {
                mu.Lock()
                valid = append(valid, proxy)
                mu.Unlock()
            }

            mu.Lock()
            checked++
            if checked%100 == 0 || checked == total {
                log.Printf("[hellcat] 🔍 Checked %d/%d proxies... (Valid: %d)", checked, total, len(valid))
            }
            mu.Unlock()
        }(p)
    }

    wg.Wait()
    return valid
}

// checkProxy делает TCP коннект и базовый SOCKS5 хендшейк
func checkProxy(p config.ProxyEntry) bool {
    addr := fmt.Sprintf("%s:%d", p.Address, p.Port)
    conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
    if err != nil {
        return false
    }
    defer conn.Close()

    // ВАЖНО: Устанавливаем дедлайн на чтение/запись, чтобы не зависнуть на "молчащих" сокетах
    conn.SetDeadline(time.Now().Add(3 * time.Second))

    // Если SOCKS5 без пароля, отправляем хендшейк
    if p.Protocol == "socks" && p.Username == "" {
        // 0x05 = SOCKS version 5, 0x01 = 1 method, 0x00 = No Auth
        _, err = conn.Write([]byte{0x05, 0x01, 0x00})
        if err != nil {
            return false
        }
        buf := make([]byte, 2)
        _, err = io.ReadFull(conn, buf)
        if err != nil {
            return false
        }
        // Ждем ответ: 0x05 (SOCKS5), 0x00 (No Auth) или 0x02 (User/Pass) или 0xFF (No methods)
        if buf[0] != 0x05 || buf[1] == 0xFF {
            return false
        }
    }
    
    // Для HTTP и SOCKS5 с паролем достаточно успешного TCP-коннекта (делать полный хендшейк слишком долго)
    return true
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
