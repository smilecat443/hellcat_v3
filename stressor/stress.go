// [hellcat]
package stressor

import (
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "runtime"
    "sync/atomic"
    "time"

    "hellcat/config"
    "hellcat/parser"
)

var stealthURLs = []string{
    "https://www.google.com/",
    "https://www.google.com/search?q=test",
    "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
    "https://www.youtube.com/",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/feed/trending",
    "https://www.facebook.com/",
    "https://www.facebook.com/login/",
    "https://www.twitter.com/",
    "https://x.com/i/flow/login",
    "https://www.instagram.com/",
    "https://www.instagram.com/accounts/login/",
    "https://www.wikipedia.org/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://en.wikipedia.org/wiki/HTTPS",
    "https://www.reddit.com/",
    "https://www.reddit.com/r/popular.json",
    "https://www.amazon.com/",
    "https://www.amazon.com/s?k=laptop",
    "https://www.cloudflare.com/",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://www.microsoft.com/",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/",
    "https://www.apple.com/shop/buy-mac/macbook-pro",
    "https://www.github.com/",
    "https://github.com/trending",
    "https://stackoverflow.com/",
    "https://stackoverflow.com/questions",
    "https://www.yahoo.com/",
    "https://www.bing.com/",
    "https://www.twitch.tv/",
    "https://www.netflix.com/",
    "https://www.linkedin.com/",
    "https://www.dropbox.com/",
    "https://drive.google.com/",
    "https://www.tiktok.com/",
    "https://www.whatsapp.com/",
    "https://www.telegram.org/",
}

var payloads = []string{
    "https://speed.cloudflare.com/__down?bytes=10737418240",
    "https://speed.cloudflare.com/__down?bytes=5368709120",
    "https://speed.cloudflare.com/__down?bytes=2147483648",
    "https://speed.cloudflare.com/__down?bytes=1073741824",
    "https://speed.cloudflare.com/__down?bytes=536870912",
    "https://speed.cloudflare.com/__down?bytes=268435456",
    "http://speedtest.tele2.net/10GB.zip",
    "http://speedtest.tele2.net/1GB.zip",
    "http://proof.ovh.net/files/10Gb.dat",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://proof.ovh.net/files/1Gb.dat",
    "https://bouygues.iperf.fr/10G.iso",
    "http://speedtest.ftp.otenet.gr/files/test1Gb.db",
}

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

var (
    requests        uint64
    errors          uint64
    bytesDownloaded uint64
    activeWorkers   int32
    stealthMode     bool
    customURL       string
)

const (
    maxConcurrentDownloadsInsane = 200
    maxDownloadBytesInsane       = 100 * 1024 * 1024
    maxGoroutines                = 50000
    stealthMaxBytes              = 2 * 1024 * 1024
)

func getRandomPort() int {
    for i := 0; i < 100; i++ {
        port := rand.Intn(55000) + 10000
        ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
        if err == nil {
            ln.Close()
            return port
        }
    }
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return 0
    }
    port := ln.Addr().(*net.TCPAddr).Port
    ln.Close()
    return port
}

func Run(cfgs []*parser.OutboundConfig, threads int, duration int, numXray int, insane bool, stealth bool, customTarget string) {
    stealthMode = stealth
    customURL = customTarget

    if customURL != "" {
        payloads = []string{customURL}
    }

    modeStr := "HEAVY"
    if stealthMode {
        modeStr = "STEALTH"
    }
    if insane {
        log.Printf("[hellcat] 🔥 INSANE %s MODE (safe limits: %d concurrent DL/proxy, %d MB max per request)",
            modeStr, maxConcurrentDownloadsInsane, maxDownloadBytesInsane/(1024*1024))
    } else {
        log.Printf("[hellcat] ⚡ Starting %s stress test", modeStr)
    }

    log.Printf("[hellcat] 📊 %d xray × %d threads", numXray, threads)
    log.Printf("[hellcat] 🎯 Loaded %d targets from list", len(cfgs))
    
    // Если больше 1 цели — выводим весь список
    if len(cfgs) > 1 {
        for i, c := range cfgs {
            log.Printf("[hellcat] 🌐 [%d/%d] %s (%s)", i+1, len(cfgs), getTargetInfo(c), c.Protocol)
        }
    } else if len(cfgs) == 1 {
        log.Printf("[hellcat] 🌐 Primary: %s (%s)", getTargetInfo(cfgs[0]), cfgs[0].Protocol)
    }

    if duration > 0 {
        log.Printf("[hellcat] ⏱️  Duration: %d sec", duration)
    }

    stop := make(chan struct{})
    if duration > 0 {
        time.AfterFunc(time.Duration(duration)*time.Second, func() {
            log.Println("[hellcat] ⏰ Stopping...")
            close(stop)
        })
    }

    proxies := make([]string, numXray)
    var configFiles []string

    log.Println("[hellcat] ⏳ Generating random configs and starting Xray instances...")
    for i := 0; i < numXray; i++ {
        cfg := cfgs[i%len(cfgs)]
        port := getRandomPort()
        confPath := config.GenerateWithPort(cfg, port)
        configFiles = append(configFiles, confPath)
        proxies[i] = fmt.Sprintf("socks5h://127.0.0.1:%d", port)
        go startXray(confPath, i, port)
        time.Sleep(150 * time.Millisecond)
    }

    log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
    waitForProxies(proxies)

    clients := make([]*http.Client, numXray)
    for i, p := range proxies {
        proxyURL, _ := url.Parse(p)
        tr := &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
            DisableKeepAlives:     false,
            MaxIdleConns:          100,
            MaxIdleConnsPerHost:   20,
            MaxConnsPerHost:       100,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ResponseHeaderTimeout: 30 * time.Second,
        }
        clients[i] = &http.Client{Transport: tr, Timeout: 0}
    }

    sem := make([]chan struct{}, numXray)
    for i := 0; i < numXray; i++ {
        if insane {
            sem[i] = make(chan struct{}, maxConcurrentDownloadsInsane)
        } else {
            sem[i] = make(chan struct{}, 30)
        }
    }

    for i := 0; i < threads; i++ {
        idx := i % numXray
        atomic.AddInt32(&activeWorkers, 1)
        go func(client *http.Client, sem chan struct{}, insane bool) {
            defer atomic.AddInt32(&activeWorkers, -1)
            for {
                select {
                case <-stop:
                    return
                default:
                    if insane && runtime.NumGoroutine() > maxGoroutines {
                        time.Sleep(10 * time.Millisecond)
                        continue
                    }
                    sem <- struct{}{}
                    go func() {
                        defer func() { <-sem }()
                        if insane {
                            if stealthMode {
                                stealthRequest(client)
                            } else {
                                downloadInsane(client)
                            }
                        } else {
                            if stealthMode {
                                stealthRequest(client)
                            } else {
                                downloadOnce(client)
                            }
                        }
                    }()
                    if !insane {
                        time.Sleep(time.Millisecond * time.Duration(rand.Intn(20)))
                    } else {
                        time.Sleep(time.Microsecond)
                    }
                }
            }
        }(clients[idx], sem[idx], insane)
    }

    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            goto cleanup
        case <-ticker.C:
            succ := atomic.SwapUint64(&requests, 0)
            atomic.SwapUint64(&errors, 0)
            bytes := atomic.SwapUint64(&bytesDownloaded, 0)
            mb := float64(bytes) / 1024 / 1024
            goroutines := runtime.NumGoroutine()
            log.Printf("[hellcat] 📈 req/s: %d | %.1f MB/s | active: %d | goroutines: %d",
                succ/5, mb/5.0, atomic.LoadInt32(&activeWorkers), goroutines)
        }
    }

cleanup:
    time.Sleep(3 * time.Second)
    for _, f := range configFiles {
        os.Remove(f)
    }
    log.Println("[hellcat] ✅ Finished.")
}

func stealthRequest(client *http.Client) {
    target := stealthURLs[rand.Intn(len(stealthURLs))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.5")
    req.Header.Set("Connection", "keep-alive")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        return
    }
    defer resp.Body.Close()

    n, _ := io.CopyN(io.Discard, resp.Body, stealthMaxBytes)
    atomic.AddUint64(&bytesDownloaded, uint64(n))
    atomic.AddUint64(&requests, 1)
}

func downloadOnce(client *http.Client) {
    u := payloads[rand.Intn(len(payloads))]
    req, _ := http.NewRequest("GET", u, nil)
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        return
    }
    defer resp.Body.Close()

    maxBytes := (1 + rand.Intn(5)) * 1024 * 1024
    n, _ := io.CopyN(io.Discard, resp.Body, int64(maxBytes))
    atomic.AddUint64(&bytesDownloaded, uint64(n))
    atomic.AddUint64(&requests, 1)
}

func downloadInsane(client *http.Client) {
    u := payloads[rand.Intn(len(payloads))]
    req, _ := http.NewRequest("GET", u, nil)
    req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        return
    }
    defer resp.Body.Close()

    n, _ := io.CopyN(io.Discard, resp.Body, int64(maxDownloadBytesInsane))
    atomic.AddUint64(&bytesDownloaded, uint64(n))
    atomic.AddUint64(&requests, 1)
}

func getTargetInfo(cfg *parser.OutboundConfig) string {
    var host string
    var port int
    var network string
    var security string

    if cfg.StreamSetting != nil {
        network = cfg.StreamSetting.Network
        security = cfg.StreamSetting.Security
    }

    switch s := cfg.Settings.(type) {
    case parser.VnextSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.VMessSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.ServerSettings:
        if len(s.Servers) > 0 {
            host = s.Servers[0].Address
            port = s.Servers[0].Port
        }
    }

    return fmt.Sprintf("%s:%d (%s/%s)", host, port, network, security)
}

func waitForProxies(proxies []string) {
    for _, proxy := range proxies {
        u, _ := url.Parse(proxy)
        addr := u.Host
        for i := 0; i < 20; i++ {
            conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
            if err == nil {
                conn.Close()
                break
            }
            time.Sleep(500 * time.Millisecond)
        }
    }
}

func startXray(configPath string, index int, port int) {
    cmd := exec.Command("xray", "-config", configPath)
    cmd.Stdout = nil
    cmd.Stderr = nil
    if err := cmd.Start(); err != nil {
        log.Printf("[hellcat] ❌ xray [%d] start: %v", index, err)
        return
    }
    log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", index, cmd.Process.Pid, port)
    go func() {
        if err := cmd.Wait(); err != nil {
            log.Printf("[hellcat] ⚠️  xray [%d] exited: %v", index, err)
        }
    }()
}
