package main

import (
    "flag"
    "log"
    "os"
    "path/filepath"

    "hellcat/parser"
    "hellcat/stressor"
)

func main() {
    
    matches, _ := filepath.Glob("config*.json")
    for _, f := range matches {
        os.Remove(f)
    }

    vlessURL := flag.String("url", "", "Proxy link (vless/vmess/trojan/ss/hy2/tuic)")
    listFile := flag.String("list", "", "File with links")
    threadCount := flag.Int("threads", 200, "Threads per proxy (default 200)")       
    duration := flag.Int("duration", 0, "Duration in seconds (0=infinite)")
    numXray := flag.Int("instances", 20, "Number of xray-core processes (default 20)") 
    insane := flag.Bool("insane", false, "Insane mode (2x workers, burst=8)")
    stealth := flag.Bool("stealth", false, "Use pseudo-load instead of heavy downloads")
    customTarget := flag.String("target", "", "Custom download URL (overrides built-in list)")
    fakelogin := flag.Bool("fakelogin", false, "Rotate UUID/Password every 1000 requests")
    flag.Parse()

    var configs []*parser.OutboundConfig

    if *vlessURL != "" {
        cfg, err := parser.Parse(*vlessURL)
        if err != nil {
            log.Fatalf("[!] Parse error: %v", err)
        }
        configs = append(configs, cfg)
    } else if *listFile != "" {
        data, err := os.ReadFile(*listFile)
        if err != nil {
            log.Fatalf("Failed to read file: %v", err)
        }
        urls := parser.Lines(string(data))
        for _, raw := range urls {
            cfg, err := parser.Parse(raw)
            if err != nil {
                log.Printf("[!] Parse error (%s): %v", raw[:min(len(raw), 40)], err)
                continue
            }
            configs = append(configs, cfg)
        }
    } else {
        log.Fatal("Specify --url or --list")
    }

    if len(configs) == 0 {
        log.Fatal("No valid proxy links found.")
    }

    stressor.Run(configs, *threadCount, *duration, *numXray, *insane, *stealth, *customTarget, *fakelogin)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
