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

var payloads = []string{
	"http://speedtest.tele2.net/10GB.zip",
	"http://proof.ovh.net/files/10Gb.dat",
	"http://ipv4.download.thinkbroadband.com/10GB.zip",
	"http://speedtest.belwue.net/10G",
	"http://speedtest.ftp.otenet.gr/files/test10Gb.db",
	"http://testfile.org/files/testfile_10GB.bin",
	"https://proof.ovh.net/files/10Gb.dat",
	"https://speedtest.tele2.net/10GB.zip",
	"https://ipv4.download.thinkbroadband.com/10GB.zip",
	"https://speed.cloudflare.com/__down?bytes=10737418240",
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"curl/7.88.1",
	"Wget/1.21",
	"Go-http-client/1.1",
}

var (
	requests        uint64
	errors          uint64
	bytesDownloaded uint64
	activeWorkers   int32
)

const (
	// Предохранители для insane-режима
	maxConcurrentDownloadsInsane = 200 // максимум одновременных загрузок на ОДИН прокси
	maxDownloadBytesInsane       = 100 * 1024 * 1024 // 100 MB на запрос (чтобы быстрее завершать)
	maxGoroutines                = 50000 // если горутин больше – приостанавливаем запуск новых
)

func Run(cfg *parser.VLESSConfig, threads int, duration int, numXray int, insane bool) {
	if insane {
		log.Printf("[hellcat] 🔥 INSANE MODE (safe limits: %d concurrent DL/proxy, %d MB max per request)",
			maxConcurrentDownloadsInsane, maxDownloadBytesInsane/(1024*1024))
	} else {
		log.Println("[hellcat] ⚡ Starting stress test")
	}

	log.Printf("[hellcat] 📊 %d xray × %d threads", numXray, threads)
	log.Printf("[hellcat] 🎯 %s:%s (%s/%s)", cfg.Host, cfg.Port, cfg.Network, cfg.Security)
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

	// Запуск xray (с плавным стартом даже в insane)
	basePort := 10808
	proxies := make([]string, numXray)
	var configFiles []string
	for i := 0; i < numXray; i++ {
		port := basePort + i
		confPath := config.GenerateWithPort(cfg, port)
		configFiles = append(configFiles, confPath)
		proxies[i] = fmt.Sprintf("socks5h://127.0.0.1:%d", port)
		go startXray(confPath, i)
		time.Sleep(150 * time.Millisecond) // плавный старт
	}
	log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
	waitForProxies(proxies)

	// HTTP клиенты с разумными лимитами
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

	// Семафоры на каждый прокси
	sem := make([]chan struct{}, numXray)
	for i := 0; i < numXray; i++ {
		if insane {
			sem[i] = make(chan struct{}, maxConcurrentDownloadsInsane)
		} else {
			sem[i] = make(chan struct{}, 30)
		}
	}

	// Запуск воркеров
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
					// Проверка на excessive goroutines
					if insane && runtime.NumGoroutine() > maxGoroutines {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					sem <- struct{}{}
					go func() {
						defer func() { <-sem }()
						if insane {
							downloadInsane(client)
						} else {
							downloadOnce(client)
						}
					}()
					if !insane {
						time.Sleep(time.Millisecond * time.Duration(rand.Intn(20)))
					} else {
						// микро-пауза для предотвращения лавины
						time.Sleep(time.Microsecond)
					}
				}
			}
		}(clients[idx], sem[idx], insane)
	}

	// Мониторинг
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			goto cleanup
		case <-ticker.C:
			succ := atomic.SwapUint64(&requests, 0)
			fail := atomic.SwapUint64(&errors, 0)
			bytes := atomic.SwapUint64(&bytesDownloaded, 0)
			total := succ + fail
			errRate := 0.0
			if total > 0 {
				errRate = float64(fail) / float64(total) * 100
			}
			mb := float64(bytes) / 1024 / 1024
			goroutines := runtime.NumGoroutine()
			log.Printf("[hellcat] 📈 req/s: %d | %.1f MB/s | err: %d (%.1f%%) | active: %d | goroutines: %d",
				succ/5, mb/5.0, fail, errRate, atomic.LoadInt32(&activeWorkers), goroutines)
		}
	}

cleanup:
	time.Sleep(3 * time.Second)
	for _, f := range configFiles {
		os.Remove(f)
	}
	log.Println("[hellcat] ✅ Finished.")
}

func downloadOnce(client *http.Client) {
	url := payloads[rand.Intn(len(payloads))]
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&errors, 1)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		atomic.AddUint64(&errors, 1)
		return
	}

	maxBytes := (1 + rand.Intn(5)) * 1024 * 1024
	io.CopyN(io.Discard, resp.Body, int64(maxBytes))
	atomic.AddUint64(&requests, 1)
}

func downloadInsane(client *http.Client) {
	url := payloads[rand.Intn(len(payloads))]
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&errors, 1)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		atomic.AddUint64(&errors, 1)
		return
	}

	// Ограничиваем объём, чтобы быстрее завершать и не копить горутины
	io.CopyN(io.Discard, resp.Body, int64(maxDownloadBytesInsane))
	atomic.AddUint64(&requests, 1)
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

func startXray(configPath string, index int) {
	cmd := exec.Command("xray", "-config", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Printf("[hellcat] ❌ xray [%d] start: %v", index, err)
		return
	}
	log.Printf("[hellcat] ✓ xray [%d] PID %d", index, cmd.Process.Pid)
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("[hellcat] ⚠️  xray [%d] exited: %v", index, err)
		}
	}()
}
