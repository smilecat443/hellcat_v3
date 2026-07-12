package config

import (
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "math/rand/v2" // Go 1.22+
    "os"
    "time"

    "hellcat/parser"
)

const TempFilePrefix = "hellcat_tmp_"

type XrayConfig struct {
    Log       *LogConfig     `json:"log,omitempty"`
    Inbounds  []XrayInbound  `json:"inbounds"`
    Outbounds []XrayOutbound `json:"outbounds"`
}

type LogConfig struct {
    LogLevel string `json:"loglevel"`
}

type XrayInbound struct {
    Port     int             `json:"port"`
    Listen   string          `json:"listen"`
    Protocol string          `json:"protocol"`
    Settings InboundSettings `json:"settings"`
}

type InboundSettings struct {
    Auth string `json:"auth"`
}

type XrayOutbound struct {
    Protocol       string          `json:"protocol"`
    Tag            string          `json:"tag,omitempty"`
    Settings       interface{}     `json:"settings"`
    StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
    Mux            *MuxConfig      `json:"mux,omitempty"`
}

type StreamSettings struct {
    Network         string      `json:"network,omitempty"`
    Security        string      `json:"security,omitempty"`
    TLSSettings     interface{} `json:"tlsSettings,omitempty"`
    RealitySettings interface{} `json:"realitySettings,omitempty"`
    WSSettings      interface{} `json:"wsSettings,omitempty"`
    GRPCSettings    interface{} `json:"grpcSettings,omitempty"`
    XHTTPSettings   interface{} `json:"xhttpSettings,omitempty"`
}

type MuxConfig struct {
    Enabled     bool `json:"enabled"`
    Concurrency int  `json:"concurrency"`
}

func GenerateWithPort(cfg *parser.OutboundConfig, port int) (fileName string, cleanup func(), err error) {
    if cfg.Protocol == "" {
        return "", nil, fmt.Errorf("empty protocol in config")
    }

    inbound := XrayInbound{
        Port:     port,
        Listen:   "127.0.0.1",
        Protocol: "socks",
        Settings: InboundSettings{Auth: "noauth"},
    }

    outbound := XrayOutbound{
        Protocol:       cfg.Protocol,
        Tag:            cfg.Tag,
        Settings:       cfg.Settings,
        StreamSettings: toStreamSettings(cfg.StreamSetting),
    }

    if cfg.Mux.Enabled {
        outbound.Mux = &MuxConfig{
            Enabled:     cfg.Mux.Enabled,
            Concurrency: cfg.Mux.Concurrency,
        }
    }

    xrayConf := XrayConfig{
        Log:       &LogConfig{LogLevel: "none"},
        Inbounds:  []XrayInbound{inbound},
        Outbounds: []XrayOutbound{outbound},
    }

    var buf bytes.Buffer
    enc := json.NewEncoder(&buf)
    enc.SetIndent("", "  ")
    if err := enc.Encode(xrayConf); err != nil {
        return "", nil, fmt.Errorf("encode config: %w", err)
    }

    randNum := rand.IntN(99999)
    fileName = fmt.Sprintf("%s%d_%d_%s_%05d.json",
        TempFilePrefix,
        os.Getpid(),
        port,
        time.Now().Format("150405.000"),
        randNum,
    )

    tmpFile := fileName + ".tmp"
    if err := os.WriteFile(tmpFile, buf.Bytes(), 0600); err != nil {
        return "", nil, fmt.Errorf("write tmp config: %w", err)
    }
    if err := os.Rename(tmpFile, fileName); err != nil {
        os.Remove(tmpFile)
        return "", nil, fmt.Errorf("rename config: %w", err)
    }

    cleanup = func() {
        if err := os.Remove(fileName); err != nil && !os.IsNotExist(err) {
            log.Printf("[!] Failed to remove temp config %s: %v", fileName, err)
        }
    }

    return fileName, cleanup, nil
}

func toStreamSettings(s *parser.StreamSetting) *StreamSettings {
    if s == nil {
        return nil
    }
    return &StreamSettings{
        Network:         s.Network,
        Security:        s.Security,
        TLSSettings:     s.TlsSettings,
        RealitySettings: s.RealitySettings,
        WSSettings:      s.WsSettings,
        GRPCSettings:    s.GRPCConfig,
        XHTTPSettings:   s.XhttpSettings,
    }
}
