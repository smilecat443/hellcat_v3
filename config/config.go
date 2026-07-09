// [hellcat]

package config

import (
    "encoding/json"
    "fmt"
    "log"
    "os"
    "time"

    "hellcat/parser"
)

type XrayConfig struct {
    Log       *LogConfig    `json:"log,omitempty"`
    Inbounds  []interface{} `json:"inbounds"`
    Outbounds []interface{} `json:"outbounds"`
}

type LogConfig struct {
    LogLevel string `json:"loglevel"`
}

func Generate(cfg *parser.OutboundConfig) string {
    return GenerateWithPort(cfg, 10808)
}

func GenerateWithPort(cfg *parser.OutboundConfig, port int) string {
    inbound := map[string]interface{}{
        "port":     port,
        "listen":   "127.0.0.1",
        "protocol": "socks",
        "settings": map[string]interface{}{"auth": "noauth"},
    }

    outbound := map[string]interface{}{
        "protocol": cfg.Protocol,
        "tag":      cfg.Tag,
        "settings": cfg.Settings,
    }

    if cfg.StreamSetting != nil {
        stream := map[string]interface{}{}
        stream["network"] = cfg.StreamSetting.Network
        stream["security"] = cfg.StreamSetting.Security

        if cfg.StreamSetting.TlsSettings != nil {
            stream["tlsSettings"] = cfg.StreamSetting.TlsSettings
        }
        if cfg.StreamSetting.RealitySettings != nil {
            stream["realitySettings"] = cfg.StreamSetting.RealitySettings
        }
        if cfg.StreamSetting.WsSettings != nil {
            stream["wsSettings"] = cfg.StreamSetting.WsSettings
        }
        if cfg.StreamSetting.GRPCConfig != nil {
            stream["grpcSettings"] = cfg.StreamSetting.GRPCConfig
        }
        if cfg.StreamSetting.XhttpSettings != nil {
            stream["xhttpSettings"] = cfg.StreamSetting.XhttpSettings
        }

        outbound["streamSettings"] = stream
    }

    if cfg.Mux.Enabled {
        outbound["mux"] = map[string]interface{}{
            "enabled":     cfg.Mux.Enabled,
            "concurrency": cfg.Mux.Concurrency,
        }
    }

    xrayConf := XrayConfig{
        Log:       &LogConfig{LogLevel: "none"},
        Inbounds:  []interface{}{inbound},
        Outbounds: []interface{}{outbound},
    }

    fileName := fmt.Sprintf("config_%d_%s.json", port, time.Now().Format("150405"))
    f, err := os.Create(fileName)
    if err != nil {
        log.Fatalf("Error writing config file: %v", err)
    }
    defer f.Close()

    encoder := json.NewEncoder(f)
    encoder.SetIndent("", "  ")
    if err := encoder.Encode(xrayConf); err != nil {
        log.Fatalf("Error encoding config JSON: %v", err)
    }

    return fileName
}
