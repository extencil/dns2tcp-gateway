package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// RTCPSession represents an active reverse TCP relay session.
// It listens on an allocated port and bridges incoming user connections
// with the DNS tunnel connection.
type RTCPSession struct {
	Port      int
	Subdomain string

	listener  net.Listener
	tunnelIn  chan net.Conn // DNS tunnel side connection arrives here
	logger    *slog.Logger
	closeOnce sync.Once
	done      chan struct{}
}

// Manager handles RTCP relay sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*RTCPSession // keyed by subdomain
	pool     *PortPool
	logger   *slog.Logger
}

// NewManager creates a new RTCP relay manager with a port pool.
func NewManager(portMin, portMax int, logger *slog.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*RTCPSession),
		pool:     NewPortPool(portMin, portMax),
		logger:   logger.With("component", "relay"),
	}
}

// Create allocates a port and starts listening for the RTCP session.
// The session waits for both a DNS tunnel connection and a user nc connection,
// then bridges them.
func (m *Manager) Create(ctx context.Context, subdomain string) (*RTCPSession, error) {
	port, err := m.pool.Allocate()
	if err != nil {
		return nil, fmt.Errorf("relay: allocating port: %w", err)
	}

	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		m.pool.Release(port)
		return nil, fmt.Errorf("relay: listening on %s: %w", addr, err)
	}

	sess := &RTCPSession{
		Port:      port,
		Subdomain: subdomain,
		listener:  listener,
		tunnelIn:  make(chan net.Conn, 1),
		logger:    m.logger.With("subdomain", subdomain, "port", port),
		done:      make(chan struct{}),
	}

	m.mu.Lock()
	m.sessions[subdomain] = sess
	m.mu.Unlock()

	go sess.acceptLoop(ctx, m)

	m.logger.Info("rtcp session created", "subdomain", subdomain, "port", port)
	return sess, nil
}

// DeliverTunnelConn delivers the DNS tunnel side connection to an RTCP session.
func (m *Manager) DeliverTunnelConn(subdomain string, conn net.Conn) error {
	m.mu.RLock()
	sess, ok := m.sessions[subdomain]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("relay: session %q not found", subdomain)
	}

	select {
	case sess.tunnelIn <- conn:
		return nil
	default:
		return fmt.Errorf("relay: session %q tunnel already connected", subdomain)
	}
}

// Remove closes and removes an RTCP session.
func (m *Manager) Remove(subdomain string) {
	m.mu.Lock()
	sess, ok := m.sessions[subdomain]
	if ok {
		delete(m.sessions, subdomain)
	}
	m.mu.Unlock()

	if ok {
		sess.close()
		m.pool.Release(sess.Port)
		m.logger.Info("rtcp session removed", "subdomain", subdomain)
	}
}

// Get returns an RTCP session by subdomain.
func (m *Manager) Get(subdomain string) (*RTCPSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[subdomain]
	return sess, ok
}

// Shutdown closes all RTCP sessions.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for sub, sess := range m.sessions {
		sess.close()
		m.pool.Release(sess.Port)
		delete(m.sessions, sub)
	}
	m.logger.Info("all rtcp sessions closed")
}

// acceptLoop accepts incoming TCP connections on the RTCP port.
// The first connection is the user (nc), which gets bridged with the tunnel connection.
func (s *RTCPSession) acceptLoop(ctx context.Context, mgr *Manager) {
	defer close(s.done)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Debug("accept error", "error", err)
				return
			}
		}

		s.logger.Info("user connected", "remote", conn.RemoteAddr())

		// Wait for the tunnel side connection (with timeout).
		select {
		case tunnelConn := <-s.tunnelIn:
			s.logger.Info("bridging connections")
			bridge(conn, tunnelConn, s.logger)
			// After bridge completes, clean up.
			mgr.Remove(s.Subdomain)
			return
		case <-time.After(5 * time.Minute):
			s.logger.Warn("tunnel connection timeout, closing user connection")
			conn.Close()
		case <-ctx.Done():
			conn.Close()
			return
		}
	}
}

func (s *RTCPSession) close() {
	s.closeOnce.Do(func() {
		s.listener.Close()
	})
}

// bridge copies data bidirectionally between two connections until one side closes.
func bridge(a, b net.Conn, logger *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn, direction string) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		if err != nil {
			logger.Debug("bridge copy done", "direction", direction, "bytes", n, "error", err)
		} else {
			logger.Debug("bridge copy done", "direction", direction, "bytes", n)
		}
		// Close write side to signal EOF to the other direction.
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(a, b, "tunnel->user")
	go copy(b, a, "user->tunnel")

	wg.Wait()
	a.Close()
	b.Close()
}
