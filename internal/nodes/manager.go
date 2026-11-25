package nodes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/client"
	"socketproxy/internal/config"
	"socketproxy/internal/plugin"
	"socketproxy/internal/relay"
)

type Strategy string

const (
	StrategyManual   Strategy = "manual"
	StrategyLatency  Strategy = "latency"
	StrategyFailover Strategy = "failover"
)

type nodeState struct {
	cfg config.Node

	once       sync.Once
	dialer     *client.Dialer
	pluginProc *plugin.Process
	initErr    error

	latency  atomic.Int64
	healthy  atomic.Bool
	checked  atomic.Bool
	failures atomic.Int32
}

// Info is a snapshot of a node's configuration and runtime state.
type Info struct {
	Name     string
	Server   string
	Port     int
	Method   string
	UDP      bool
	Latency  time.Duration
	Healthy  bool
	Checked  bool
	Failures int
}

// Manager selects a node per connection according to a strategy and tracks
// node health.
type Manager struct {
	mu       sync.RWMutex
	nodes    []*nodeState
	byName   map[string]*nodeState
	current  int
	strategy Strategy

	healthInterval time.Duration
	healthTimeout  time.Duration

	// lastUsed is the index of the node most recently used successfully.
	lastUsed atomic.Int32

	// Logf, when set, receives failover diagnostics.
	Logf func(format string, args ...any)
}

func NewManager(cfg *config.ClientConfig) (*Manager, error) {
	if len(cfg.Nodes) == 0 {
		return nil, errors.New("no nodes configured")
	}

	strategy := Strategy(cfg.Strategy)
	if strategy == "" {
		strategy = StrategyManual
	}
	switch strategy {
	case StrategyManual, StrategyLatency, StrategyFailover:
	default:
		return nil, fmt.Errorf("unknown strategy %q", cfg.Strategy)
	}

	m := &Manager{
		byName:         make(map[string]*nodeState),
		strategy:       strategy,
		healthInterval: 30 * time.Second,
		healthTimeout:  3 * time.Second,
	}
	m.lastUsed.Store(-1)
	if cfg.HealthCheck != nil {
		if cfg.HealthCheck.Interval > 0 {
			m.healthInterval = time.Duration(cfg.HealthCheck.Interval) * time.Second
		}
		if cfg.HealthCheck.Timeout > 0 {
			m.healthTimeout = time.Duration(cfg.HealthCheck.Timeout) * time.Second
		}
	}

	for _, n := range cfg.Nodes {
		ns, err := newNodeState(n)
		if err != nil {
			return nil, err
		}
		if _, dup := m.byName[n.Name]; dup {
			return nil, fmt.Errorf("duplicate node name %q", n.Name)
		}
		m.nodes = append(m.nodes, ns)
		m.byName[n.Name] = ns
	}

	if cfg.Node != "" {
		idx, ok := m.indexOf(cfg.Node)
		if !ok {
			return nil, fmt.Errorf("node %q not found", cfg.Node)
		}
		m.current = idx
	}
	return m, nil
}

func newNodeState(n config.Node) (*nodeState, error) {
	if _, err := cipher.FromName(n.Method); err != nil {
		return nil, fmt.Errorf("node %q: %w", n.Name, err)
	}
	return &nodeState{cfg: n}, nil
}

func (ns *nodeState) getDialer() (*client.Dialer, error) {
	ns.once.Do(func() {
		ns.dialer, ns.pluginProc, ns.initErr = ns.buildDialer()
	})
	if ns.dialer == nil && ns.initErr == nil {
		return nil, errors.New("node is closed")
	}
	return ns.dialer, ns.initErr
}

func (ns *nodeState) buildDialer() (*client.Dialer, *plugin.Process, error) {
	target := ns.cfg

	var proc *plugin.Process
	if ns.cfg.Plugin != "" {
		p, addr, err := plugin.StartClient(
			ns.cfg.Plugin, ns.cfg.Server, ns.cfg.Port,
			ns.cfg.PluginOpts, ns.cfg.PluginArgs, 10*time.Second,
		)
		if err != nil {
			return nil, nil, err
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			p.Close()
			return nil, nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			p.Close()
			return nil, nil, err
		}
		target.Server = host
		target.Port = port
		proc = p
	}

	dialer, err := client.New(target)
	if err != nil {
		if proc != nil {
			proc.Close()
		}
		return nil, nil, err
	}
	return dialer, proc, nil
}

func (ns *nodeState) close() {
	ns.once.Do(func() {})
	if ns.pluginProc != nil {
		ns.pluginProc.Close()
	}
}

func (m *Manager) indexOf(name string) (int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i, ns := range m.nodes {
		if ns.cfg.Name == name {
			return i, true
		}
	}
	return 0, false
}

func (m *Manager) nodeAt(i int) *nodeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if i < 0 || i >= len(m.nodes) {
		return nil
	}
	return m.nodes[i]
}

func (m *Manager) Strategy() Strategy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy
}

func (m *Manager) SetCurrent(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ns := range m.nodes {
		if ns.cfg.Name == name {
			m.current = i
			return nil
		}
	}
	return fmt.Errorf("node %q not found", name)
}

func (m *Manager) Current() config.Node {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.nodes) == 0 {
		return config.Node{}
	}
	return m.nodes[m.current].cfg
}

func (m *Manager) Infos() []Info {
	m.mu.RLock()
	nodes := make([]*nodeState, len(m.nodes))
	copy(nodes, m.nodes)
	m.mu.RUnlock()

	infos := make([]Info, 0, len(nodes))
	for _, ns := range nodes {
		infos = append(infos, Info{
			Name:     ns.cfg.Name,
			Server:   ns.cfg.Server,
			Port:     ns.cfg.Port,
			Method:   ns.cfg.Method,
			UDP:      ns.cfg.UDP,
			Latency:  time.Duration(ns.latency.Load()),
			Healthy:  ns.healthy.Load(),
			Checked:  ns.checked.Load(),
			Failures: int(ns.failures.Load()),
		})
	}
	return infos
}

func nodeScore(ns *nodeState) int {
	if ns.healthy.Load() {
		return 0
	}
	if !ns.checked.Load() {
		return 1
	}
	return 2
}

func lessNode(a, b *nodeState) bool {
	sa, sb := nodeScore(a), nodeScore(b)
	if sa != sb {
		return sa < sb
	}
	return a.latency.Load() < b.latency.Load()
}

func (m *Manager) order() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n := len(m.nodes)
	switch m.strategy {
	case StrategyManual:
		// Prefer the configured node, but fall back to other nodes when it is
		// known to be down or fails to connect.
		idx := make([]int, 0, n)
		cur := m.nodes[m.current]
		if !(cur.checked.Load() && !cur.healthy.Load()) {
			idx = append(idx, m.current)
		}
		rest := make([]int, 0, n-1)
		for i := 0; i < n; i++ {
			if i != m.current {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(rest, func(a, b int) bool {
			return lessNode(m.nodes[rest[a]], m.nodes[rest[b]])
		})
		result := append(idx, rest...)
		if len(result) == 0 {
			result = []int{m.current}
		}
		return result
	case StrategyLatency:
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool {
			return lessNode(m.nodes[idx[a]], m.nodes[idx[b]])
		})
		return idx
	default: // failover: current first, then best of the rest
		idx := make([]int, 0, n)
		idx = append(idx, m.current)
		rest := make([]int, 0, n-1)
		for i := 0; i < n; i++ {
			if i != m.current {
				rest = append(rest, i)
			}
		}
		sort.SliceStable(rest, func(a, b int) bool {
			return lessNode(m.nodes[rest[a]], m.nodes[rest[b]])
		})
		return append(idx, rest...)
	}
}

func (m *Manager) promote(idx int) {
	m.mu.Lock()
	if m.strategy != StrategyManual && idx != m.current {
		m.current = idx
	}
	m.mu.Unlock()
}

// noteUsed records the node used for a connection and logs when it changes.
func (m *Manager) noteUsed(idx int) {
	if m.Logf == nil {
		return
	}
	prev := m.lastUsed.Swap(int32(idx))
	if prev == int32(idx) {
		return
	}
	ns := m.nodeAt(idx)
	if ns == nil {
		return
	}
	if prev >= 0 {
		if from := m.nodeAt(int(prev)); from != nil {
			m.Logf("switch node: %q (%s:%d, %s) -> %q (%s:%d, %s)",
				from.cfg.Name, from.cfg.Server, from.cfg.Port, from.cfg.Method,
				ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, ns.cfg.Method)
			return
		}
	}
	m.Logf("using node %q (%s:%d, %s)", ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, ns.cfg.Method)
}

func (m *Manager) advanceCurrent() {
	m.mu.Lock()
	if len(m.nodes) > 0 {
		m.current = (m.current + 1) % len(m.nodes)
	}
	m.mu.Unlock()
}

// Dial opens a proxied TCP connection, failing over to other nodes when the
// strategy allows it.
func (m *Manager) Dial(target string) (net.Conn, error) {
	order := m.order()
	var lastErr error
	for _, idx := range order {
		ns := m.nodeAt(idx)
		if ns == nil {
			continue
		}
		dialer, err := ns.getDialer()
		if err != nil {
			ns.failures.Add(1)
			ns.healthy.Store(false)
			ns.checked.Store(true)
			lastErr = err
			if m.Logf != nil {
				m.Logf("node %q (%s:%d) setup failed: %v", ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, err)
			}
			if m.Strategy() == StrategyFailover {
				m.advanceCurrent()
			}
			continue
		}
		conn, err := dialer.Dial(target)
		if err == nil {
			ns.failures.Store(0)
			ns.healthy.Store(true)
			m.promote(idx)
			m.noteUsed(idx)
			return conn, nil
		}
		ns.failures.Add(1)
		ns.healthy.Store(false)
		ns.checked.Store(true)
		lastErr = err
		if m.Logf != nil {
			m.Logf("node %q (%s:%d) dial failed: %v", ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, err)
		}
		if m.Strategy() == StrategyFailover {
			m.advanceCurrent()
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no nodes available")
	}
	return nil, lastErr
}

// DialUDP opens a proxied UDP connection on the first UDP-capable node.
func (m *Manager) DialUDP() (relay.PacketConn, error) {
	order := m.order()
	var lastErr error
	for _, idx := range order {
		ns := m.nodeAt(idx)
		if ns == nil || !ns.cfg.UDP {
			continue
		}
		if ns.cfg.Plugin != "" {
			lastErr = fmt.Errorf("node %q: udp is not supported with a plugin", ns.cfg.Name)
			continue
		}
		dialer, err := ns.getDialer()
		if err != nil {
			ns.failures.Add(1)
			ns.healthy.Store(false)
			ns.checked.Store(true)
			lastErr = err
			if m.Logf != nil {
				m.Logf("node %q (%s:%d) setup failed: %v", ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, err)
			}
			continue
		}
		conn, err := dialer.DialUDP()
		if err == nil {
			ns.failures.Store(0)
			ns.healthy.Store(true)
			m.promote(idx)
			m.noteUsed(idx)
			return conn, nil
		}
		ns.failures.Add(1)
		ns.healthy.Store(false)
		ns.checked.Store(true)
		lastErr = err
		if m.Logf != nil {
			m.Logf("node %q (%s:%d) udp dial failed: %v", ns.cfg.Name, ns.cfg.Server, ns.cfg.Port, err)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no udp-capable node available")
	}
	return nil, lastErr
}

// Close stops all plugin processes started by the manager.
func (m *Manager) Close() error {
	m.mu.RLock()
	nodes := make([]*nodeState, len(m.nodes))
	copy(nodes, m.nodes)
	m.mu.RUnlock()

	for _, ns := range nodes {
		ns.close()
	}
	return nil
}

func (m *Manager) probe(ctx context.Context, ns *nodeState) {
	addr := net.JoinHostPort(ns.cfg.Server, strconv.Itoa(ns.cfg.Port))
	d := net.Dialer{Timeout: m.healthTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	ns.checked.Store(true)
	if err != nil {
		ns.healthy.Store(false)
		return
	}
	conn.Close()
	ns.latency.Store(int64(time.Since(start)))
	ns.healthy.Store(true)
	ns.failures.Store(0)
}

// CheckAll probes every node once.
func (m *Manager) CheckAll(ctx context.Context) {
	m.mu.RLock()
	nodes := make([]*nodeState, len(m.nodes))
	copy(nodes, m.nodes)
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, ns := range nodes {
		wg.Add(1)
		go func(ns *nodeState) {
			defer wg.Done()
			m.probe(ctx, ns)
		}(ns)
	}
	wg.Wait()
}

// RunHealthCheck probes nodes immediately and then periodically until ctx is
// canceled.
func (m *Manager) RunHealthCheck(ctx context.Context) {
	m.CheckAll(ctx)

	ticker := time.NewTicker(m.healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.CheckAll(ctx)
		}
	}
}

// UpdateNodes replaces the node list, preserving the current node by name when
// possible.
func (m *Manager) UpdateNodes(list []config.Node) error {
	if len(list) == 0 {
		return errors.New("empty node list")
	}

	newNodes := make([]*nodeState, 0, len(list))
	byName := make(map[string]*nodeState, len(list))
	for _, n := range list {
		ns, err := newNodeState(n)
		if err != nil {
			return err
		}
		if _, dup := byName[n.Name]; dup {
			return fmt.Errorf("duplicate node name %q", n.Name)
		}
		newNodes = append(newNodes, ns)
		byName[n.Name] = ns
	}

	m.mu.Lock()
	curName := ""
	if len(m.nodes) > 0 {
		curName = m.nodes[m.current].cfg.Name
	}
	old := m.nodes
	m.nodes = newNodes
	m.byName = byName
	m.current = 0
	m.lastUsed.Store(-1)
	if curName != "" {
		for i, ns := range newNodes {
			if ns.cfg.Name == curName {
				m.current = i
				break
			}
		}
	}
	m.mu.Unlock()

	for _, ns := range old {
		ns.close()
	}
	return nil
}

// UpdateFromSubscription fetches and applies a subscription, returning the
// number of nodes loaded.
func (m *Manager) UpdateFromSubscription(url string, timeout time.Duration) (int, error) {
	list, err := FetchSubscription(url, timeout)
	if err != nil {
		return 0, err
	}
	if err := m.UpdateNodes(list); err != nil {
		return 0, err
	}
	return len(list), nil
}
