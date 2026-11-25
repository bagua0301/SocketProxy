package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"socketproxy/internal/config"
	"socketproxy/internal/httpproxy"
	"socketproxy/internal/nodes"
	"socketproxy/internal/route"
	"socketproxy/internal/socks5"
	"socketproxy/internal/sysproxy"
)

func main() {
	if err := run(); err != nil {
		log.Printf("sp-client: %v", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "configs/client.json", "path to client config")
	nodeName := flag.String("node", "", "node name to use (defaults to config node or first)")
	flag.Parse()

	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	mgr, err := nodes.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("create node manager: %w", err)
	}
	mgr.Logf = log.Printf
	defer mgr.Close()

	if cfg.Subscription != nil && cfg.Subscription.URL != "" {
		loadSubscription(mgr, cfg.Subscription)
	}

	if *nodeName != "" {
		if err := mgr.SetCurrent(*nodeName); err != nil {
			return fmt.Errorf("select node: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.Subscription != nil && cfg.Subscription.URL != "" {
		interval := time.Duration(cfg.Subscription.UpdateInterval) * time.Second
		if interval <= 0 {
			interval = time.Hour
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					loadSubscription(mgr, cfg.Subscription)
				}
			}
		}()
	}

	go mgr.RunHealthCheck(ctx)

	router := &route.Dialer{
		Proxy:         mgr.Dial,
		Mode:          cfg.Mode,
		DirectTimeout: cfg.DirectTimeoutDuration(),
		Logf:          log.Printf,
	}

	srv := socks5.New(cfg.Listen, router.Dial)
	if cfg.Mode != route.ModeDirect {
		srv.DialUDP = mgr.DialUDP
	}
	if cfg.Auth != nil && cfg.Auth.Username != "" {
		srv.Auth = &socks5.Credentials{Username: cfg.Auth.Username, Password: cfg.Auth.Password}
		log.Printf("socks5 username/password auth enabled for user %q", cfg.Auth.Username)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var httpLn net.Listener
	if !cfg.DisableSystemProxy && sysproxy.Supported() {
		httpLn, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			ln.Close()
			return fmt.Errorf("http proxy listen: %w", err)
		}

		httpSrv := httpproxy.New(httpLn.Addr().String(), router.Dial)
		go func() {
			if err := httpSrv.Serve(httpLn); err != nil && sigCtx.Err() == nil {
				log.Printf("http proxy stopped: %v", err)
			}
		}()
		log.Printf("http proxy listening on %s", httpLn.Addr())

		restore, err := sysproxy.Configure(httpLn.Addr().String())
		if err != nil {
			log.Printf("system proxy setup failed: %v", err)
		} else {
			log.Printf("system proxy set: %s (HTTP proxy, restored on exit)", httpLn.Addr())
			defer func() {
				if err := restore(); err != nil {
					log.Printf("restore system proxy: %v", err)
				} else {
					log.Printf("system proxy restored")
				}
			}()
		}
	}
	if httpLn != nil {
		defer httpLn.Close()
	}

	cur := mgr.Current()
	log.Printf("socks5 listening on %s mode=%s strategy=%s node=%q (%s:%d, %s)",
		ln.Addr(), cfg.Mode, mgr.Strategy(), cur.Name, cur.Server, cur.Port, cur.Method)

	go func() {
		<-sigCtx.Done()
		ln.Close()
		if httpLn != nil {
			httpLn.Close()
		}
	}()

	if err := srv.Serve(ln); err != nil {
		if sigCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("socks5 server: %w", err)
	}
	return nil
}

func loadSubscription(mgr *nodes.Manager, sub *config.Subscription) {
	count, err := mgr.UpdateFromSubscription(sub.URL, 15*time.Second)
	if err != nil {
		log.Printf("subscription update failed: %v", err)
		return
	}
	log.Printf("subscription loaded %d nodes", count)
}
