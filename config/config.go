package config

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "math/rand/v2" // Go 1.22+
    "net/url"
    "os"
    "strconv"
    "strings"
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
    ProxySettings  *ProxySettings  `json:"proxySettings,omitempty"`
}

type ProxySettings struct {
    Tag string `json:"tag,omitempty"`
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

// ----- Proxy chain types -----

type ProxyServer struct {
    Address string      `json:"address"`
    Port    int         `json:"port"`
    Users   []ProxyUser `json:"users,omitempty"`
}

type ProxyUser struct {
    User string `json:"user"`
    Pass string `json:"pass"`
}

type SocksOutboundSettings struct {
    Servers []ProxyServer `json:"servers"`
}

type HttpOutboundSettings struct {
    Servers []ProxyServer `json:"servers"`
}

// ProxyEntry — upstream-прокси из файла
type ProxyEntry struct {
    Protocol string // "socks" или "http"
    Address  string
    Port     int
    Username string
    Password string
    Raw      string
}

// ParseProxyURL парсит строки вида:
//   socks5://user:pass@host:port
//   socks5://host:port
//   http://host:port
//   host:port   (по умолчанию socks5)
func ParseProxyURL(raw string) (*ProxyEntry, error) {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return nil, fmt.Errorf("empty proxy")
    }

    p := &ProxyEntry{Raw: raw}

    // Если нет схемы — добавляем socks5://
    if !strings.Contains(raw, "://") {
        raw = "socks5://" + raw
    }

    u, err := url.Parse(raw)
    if err != nil {
        return nil, fmt.Errorf("parse: %w", err)
    }

    switch strings.ToLower(u.Scheme) {
    case "socks5", "socks5h", "socks", "socks4", "socks4a":
        p.Protocol = "socks"
    case "http", "https":
        p.Protocol = "http"
    default:
        return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
    }

    if u.Hostname() == "" {
        return nil, fmt.Errorf("missing host")
    }
    p.Address = u.Hostname()

    portStr := u.Port()
    if portStr == "" {
        if p.Protocol == "socks" {
            portStr = "1080"
        } else {
            portStr = "8080"
        }
    }
    port, err := strconv.Atoi(portStr)
    if err != nil {
        return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
    }
    p.Port = port

    if u.User != nil {
        p.Username = u.User.Username()
        if pass, ok := u.User.Password(); ok {
            p.Password = pass
        }
    }
    return p, nil
}

// LoadProxyList читает файл и возвращает слайс проксей.
func LoadProxyList(path string) ([]ProxyEntry, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("open proxy list %q: %w", path, err)
    }
    defer f.Close()

    var entries []ProxyEntry
    sc := bufio.NewScanner(f)
    sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        p, err := ParseProxyURL(line)
        if err != nil {
            log.Printf("[!] Skipping proxy %q: %v", line, err)
            continue
        }
        entries = append(entries, *p)
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    if len(entries) == 0 {
        return nil, fmt.Errorf("no valid proxies in %q", path)
    }
    return entries, nil
}

// ToOutbound строит xray outbound для upstream-прокси.
func (p *ProxyEntry) ToOutbound(tag string) XrayOutbound {
    srv := ProxyServer{Address: p.Address, Port: p.Port}
    if p.Username != "" || p.Password != "" {
        srv.Users = []ProxyUser{{User: p.Username, Pass: p.Password}}
    }
    if p.Protocol == "http" {
        return XrayOutbound{
            Protocol: "http",
            Tag:      tag,
            Settings: HttpOutboundSettings{Servers: []ProxyServer{srv}},
        }
    }
    return XrayOutbound{
        Protocol: "socks",
        Tag:      tag,
        Settings: SocksOutboundSettings{Servers: []ProxyServer{srv}},
    }
}

// GenerateWithPort теперь принимает chainProxy (может быть nil).
func GenerateWithPort(cfg *parser.OutboundConfig, port int, chainProxy *ProxyEntry) (fileName string, cleanup func(), err error) {
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

    outbounds := []XrayOutbound{outbound}

    // chain: основной outbound будет ходить через proxy_chain
    if chainProxy != nil {
        proxyOut := chainProxy.ToOutbound("proxy_chain")
        outbounds = append(outbounds, proxyOut)
        outbounds[0].ProxySettings = &ProxySettings{Tag: "proxy_chain"}
    }

    xrayConf := XrayConfig{
        Log:       &LogConfig{LogLevel: "warning"},
        Inbounds:  []XrayInbound{inbound},
        Outbounds: outbounds,
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
