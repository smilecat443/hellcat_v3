// [hellcat]

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
    threadCount := flag.Int("threads", 50, "Threads per proxy")
    duration := flag.Int("duration", 0, "Duration in seconds (0=infinite)")
    numXray := flag.Int("instances", 10, "Number of xray-core processes")
    insane := flag.Bool("insane", false, "Insane mode")
    stealth := flag.Bool("stealth", false, "Use pseudo-load (Google/YouTube/etc.) instead of heavy downloads")
    customTarget := flag.String("target", "", "Custom download URL (overrides built-in list)")
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
                log.Printf("[!] Parse error (%s): %v", raw[:min(40, len(raw))], err)
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

    stressor.Run(configs, *threadCount, *duration, *numXray, *insane, *stealth, *customTarget)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
