package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/plugin"
	"socketproxy/internal/server"
)

func main() {
	configPath := flag.String("config", "configs/server.json", "path to server config")
	flag.Parse()

	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	method, err := cipher.FromName(cfg.Method)
	if err != nil {
		log.Fatalf("cipher method: %v", err)
	}
	key := crypto.EVPBytesToKey(cfg.Password, method.KeySize())

	listenAddr := cfg.Listen
	udpAddr := cfg.UDPListenAddr()

	if cfg.Plugin != "" {
		host, portStr, err := net.SplitHostPort(cfg.Listen)
		if err != nil {
			log.Fatalf("invalid listen address %q: %v", cfg.Listen, err)
		}
		publicPort, err := strconv.Atoi(portStr)
		if err != nil {
			log.Fatalf("invalid listen port %q: %v", portStr, err)
		}
		localPort, err := plugin.FreePort()
		if err != nil {
			log.Fatalf("allocate local port: %v", err)
		}

		listenAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
		udpAddr = ""

		proc, err := plugin.StartServer(cfg.Plugin, host, publicPort, "127.0.0.1", localPort, cfg.PluginOpts, cfg.PluginArgs, 15*time.Second)
		if err != nil {
			log.Fatalf("start plugin: %v", err)
		}
		defer proc.Close()
		log.Printf("plugin %q listening on %s -> ss server %s", cfg.Plugin, cfg.Listen, listenAddr)
	}

	srv := server.New(listenAddr, method, key, cfg.TimeoutDuration())
	srv.UDPAddr = udpAddr
	log.Printf("ss server listening on %s (udp %q) method=%s", listenAddr, srv.UDPAddr, cfg.Method)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ss server: %v", err)
	}
}
