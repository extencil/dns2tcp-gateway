package tunnel

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// Resource defines a named TCP forwarding target.
type Resource struct {
	Name string
	Host string
	Port int
}

func (r Resource) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// Manager handles dns2tcp tunnel protocol sessions.
// It is the bridge between the DNS server and TCP backends.
type Manager struct {
	mu      sync.RWMutex
	clients map[uint16]*Client // keyed by session ID

	store  session.Store
	logger *slog.Logger
	key    string // shared authentication key, empty = no auth
}

// NewManager creates a new tunnel manager.
func NewManager(store session.Store, key string, logger *slog.Logger) *Manager {
	return &Manager{
		clients: make(map[uint16]*Client),
		store:   store,
		key:     key,
		logger:  logger.With("component", "tunnel"),
	}
}

// HandleQuery processes an incoming dns2tcp protocol query and returns a response packet.
func (m *Manager) HandleQuery(ctx context.Context, q *protocol.ParsedQuery) (*protocol.Packet, error) {
	if q.Packet == nil {
		return nil, fmt.Errorf("tunnel: nil packet in query")
	}

	switch q.Command {
	case protocol.CmdAuth:
		return m.handleAuth(q.Packet)
	case protocol.CmdResource:
		return m.handleResource(ctx, q.Packet)
	case protocol.CmdConnect:
		return m.handleConnect(ctx, q.Packet)
	case "":
		// Data or NOP query.
		return m.handleData(q.Packet)
	default:
		return nil, fmt.Errorf("tunnel: unknown command %q", q.Command)
	}
}

func (m *Manager) handleAuth(pkt *protocol.Packet) (*protocol.Packet, error) {
	if pkt.SessionID == 0 {
		// Step 1: Client requests challenge. Create new session.
		sessionID, err := m.generateSessionID()
		if err != nil {
			return nil, err
		}

		challenge, err := protocol.GenerateChallenge()
		if err != nil {
			return nil, err
		}

		client := NewClient(sessionID, m.logger)
		client.Challenge = challenge

		m.mu.Lock()
		m.clients[sessionID] = client
		m.mu.Unlock()

		m.logger.Info("auth challenge sent", "session_id", sessionID)

		return &protocol.Packet{
			SessionID: sessionID,
			Type:      protocol.TypeOK,
			Payload:   []byte(challenge),
		}, nil
	}

	// Step 2: Client sends HMAC response.
	m.mu.RLock()
	client, ok := m.clients[pkt.SessionID]
	m.mu.RUnlock()

	if !ok {
		return &protocol.Packet{
			SessionID: pkt.SessionID,
			Type:      protocol.TypeErr,
			Payload:   []byte("unknown session"),
		}, nil
	}

	// If no key configured, accept any auth.
	if m.key != "" {
		clientHMAC := string(pkt.Payload)
		if !protocol.VerifyHMAC(m.key, client.Challenge, clientHMAC) {
			m.logger.Warn("auth failed", "session_id", pkt.SessionID)
			m.removeClient(pkt.SessionID)
			return &protocol.Packet{
				SessionID: pkt.SessionID,
				Type:      protocol.TypeErr,
				Payload:   []byte("auth failed"),
			}, nil
		}
	}

	client.IsAuthed = true
	m.logger.Info("auth success", "session_id", pkt.SessionID)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
	}, nil
}

func (m *Manager) handleResource(ctx context.Context, pkt *protocol.Packet) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil || !client.IsAuthed {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}

	// Build resource list from active sessions that match this tunnel's needs.
	// For each TCP session in the store, return it as an available resource.
	// Format matches dns2tcp: "name:host:port"
	resourceList := m.buildResourceList(ctx, pkt.SessionID)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
		Payload:   []byte(resourceList),
	}, nil
}

func (m *Manager) handleConnect(ctx context.Context, pkt *protocol.Packet) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil || !client.IsAuthed {
		return m.errPacket(pkt.SessionID, "not authenticated"), nil
	}

	resourceName := string(pkt.Payload)
	client.Resource = resourceName

	// Find the target for this resource by looking up sessions in the store.
	target := m.resolveResource(ctx, resourceName)
	if target == "" {
		m.logger.Warn("resource not found", "resource", resourceName, "session_id", pkt.SessionID)
		return m.errPacket(pkt.SessionID, "resource not found"), nil
	}

	if err := client.ConnectTCP(target); err != nil {
		m.logger.Error("tcp connect failed", "target", target, "error", err)
		return m.errPacket(pkt.SessionID, "connection failed"), nil
	}

	m.logger.Info("tunnel connected", "session_id", pkt.SessionID, "resource", resourceName, "target", target)

	return &protocol.Packet{
		SessionID: pkt.SessionID,
		Type:      protocol.TypeOK,
	}, nil
}

func (m *Manager) handleData(pkt *protocol.Packet) (*protocol.Packet, error) {
	client := m.getClient(pkt.SessionID)
	if client == nil {
		return m.errPacket(pkt.SessionID, "unknown session"), nil
	}

	if pkt.IsDesauth() {
		m.logger.Info("client disconnect", "session_id", pkt.SessionID)
		client.Close()
		m.removeClient(pkt.SessionID)
		return &protocol.Packet{
			SessionID: pkt.SessionID,
			Type:      protocol.TypeOK,
		}, nil
	}

	// If the packet carries data, forward it to the TCP backend.
	if pkt.IsData() && len(pkt.Payload) > 0 {
		if err := client.HandleData(pkt.Payload); err != nil {
			m.logger.Debug("data forward failed", "error", err, "session_id", pkt.SessionID)
		}
	}

	// Drain pending TCP data into the DNS response.
	return client.DrainPending(pkt.Seq, MaxPayloadSize), nil
}

// resolveResource maps a dns2tcp resource name to a TCP target address.
// It searches the session store for TCP-mode sessions whose subdomain
// matches the resource name, or uses the resource name directly as a fallback.
func (m *Manager) resolveResource(ctx context.Context, resourceName string) string {
	// First, check if any session subdomain matches the resource name.
	sess, ok := m.store.Get(ctx, resourceName)
	if ok && sess.Mode == session.ModeTCP {
		return sess.Target()
	}

	// Walk all sessions to find one whose subdomain is used as the tunnel domain.
	// This handles the case where the client connects to <subdomain>.<zone>
	// and the resource name in the connect command references that session.
	return ""
}

// buildResourceList returns a newline-separated list of available resources.
func (m *Manager) buildResourceList(ctx context.Context, _ uint16) string {
	// For now, return a static resource. In production this would
	// enumerate TCP sessions available to this tunnel client.
	return "tunnel:127.0.0.1:0"
}

func (m *Manager) getClient(id uint16) *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[id]
}

func (m *Manager) removeClient(id uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[id]; ok {
		c.Close()
		delete(m.clients, id)
	}
}

func (m *Manager) errPacket(sessionID uint16, msg string) *protocol.Packet {
	return &protocol.Packet{
		SessionID: sessionID,
		Type:      protocol.TypeErr,
		Payload:   []byte(msg),
	}
}

func (m *Manager) generateSessionID() (uint16, error) {
	for i := 0; i < 100; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(0xFFFF))
		if err != nil {
			return 0, fmt.Errorf("tunnel: generating session id: %w", err)
		}
		id := uint16(n.Int64()) + 1 // avoid zero

		m.mu.RLock()
		_, exists := m.clients[id]
		m.mu.RUnlock()

		if !exists {
			return id, nil
		}
	}
	return 0, fmt.Errorf("tunnel: failed to generate unique session id after 100 attempts")
}

// Shutdown closes all active tunnel clients.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, client := range m.clients {
		client.Close()
		delete(m.clients, id)
	}
	m.logger.Info("all tunnel clients closed")
}
