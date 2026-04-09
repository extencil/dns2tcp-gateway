package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/protocol"
)

const (
	// QueueSize matches dns2tcp's QUEUE_SIZE (max pending queries per client).
	QueueSize = 48

	// MaxPayloadSize is the max raw bytes that can fit in a single DNS response
	// after accounting for headers, base64 expansion, and DNS overhead.
	// Conservative estimate for 512-byte DNS packets.
	MaxPayloadSize = 100

	// ReadBufferSize is the TCP read buffer size.
	ReadBufferSize = 4096

	// DrainWait is how long DrainPending waits for TCP backend data before
	// returning a NOP response. Keep this well under typical resolver retry
	// timeout (~500ms for Cloudflare) to avoid duplicate queries.
	DrainWait = 100 * time.Millisecond
)

// Client represents an authenticated dns2tcp tunnel client.
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Subdomain string
	Challenge string
	IsAuthed  bool
	Resource  string
	NumSeq    uint16

	// TCP connection to the backend resource.
	tcpConn net.Conn

	// Pending response data read from the TCP backend, waiting to be sent
	// back via DNS responses when the client polls with NOP queries.
	pendingData []byte

	// Signaled (non-blocking) by readLoop when new data is buffered
	// or when the TCP connection closes.
	dataReady chan struct{}

	// Guards against concurrent ConnectTCP calls (dns2tcpc sends =connect twice).
	connecting bool

	// Last sequence number whose data was forwarded to TCP backend.
	// Used to deduplicate when DNS resolvers retry the same query.
	lastFwdSeq uint16

	// Tracks whether the TCP connection has been closed.
	isClosed bool

	logger *slog.Logger
}

// NewClient creates a new unauthenticated client with the given session ID.
func NewClient(sessionID uint16, logger *slog.Logger) *Client {
	return &Client{
		SessionID: sessionID,
		NumSeq:    1,
		dataReady: make(chan struct{}, 1),
		logger:    logger.With("session_id", sessionID),
	}
}

// ConnectTCP opens a TCP connection to the target resource.
// If a connection is already established or in progress, this is a no-op
// (dns2tcpc sends =connect twice; the second call must not create a duplicate).
func (c *Client) ConnectTCP(target string) error {
	c.mu.Lock()
	if c.tcpConn != nil || c.connecting {
		c.mu.Unlock()
		c.logger.Debug("tcp already connected or connecting, ignoring", "target", target)
		return nil
	}
	c.connecting = true
	c.mu.Unlock()

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)

	c.mu.Lock()
	c.connecting = false
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("tunnel: connecting to %s: %w", target, err)
	}
	c.tcpConn = conn
	c.mu.Unlock()

	c.logger.Info("tcp connection established", "target", target)

	// Start background reader that pulls data from the TCP backend.
	go c.readLoop()

	return nil
}

// readLoop reads data from the TCP backend and buffers it for DNS responses.
// It signals dataReady so DrainPending can wake up and deliver the data.
func (c *Client) readLoop() {
	buf := make([]byte, ReadBufferSize)
	for {
		n, err := c.tcpConn.Read(buf)
		if n > 0 {
			c.mu.Lock()
			c.pendingData = append(c.pendingData, buf[:n]...)
			c.mu.Unlock()
			c.signalDataReady()
			c.logger.Debug("tcp data buffered", "bytes", n, "pending", len(c.pendingData))
		}
		if err != nil {
			if err != io.EOF {
				c.logger.Debug("tcp read error", "error", err)
			}
			c.mu.Lock()
			c.isClosed = true
			c.mu.Unlock()
			c.signalDataReady()
			c.logger.Info("tcp connection closed")
			return
		}
	}
}

// signalDataReady wakes up any goroutine waiting in DrainPending.
func (c *Client) signalDataReady() {
	select {
	case c.dataReady <- struct{}{}:
	default:
	}
}

// HandleData processes incoming TCP data from the client (received via DNS query)
// and writes it to the backend TCP connection. The seq parameter deduplicates
// retried queries from DNS resolvers.
func (c *Client) HandleData(seq uint16, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn == nil {
		return fmt.Errorf("tunnel: no tcp connection")
	}
	if c.isClosed {
		return fmt.Errorf("tunnel: tcp connection closed")
	}

	// Deduplicate: resolver retries send the same query (same seq) again.
	if seq != 0 && seq == c.lastFwdSeq {
		c.logger.Debug("duplicate data seq, skipping forward", "seq", seq)
		return nil
	}
	c.lastFwdSeq = seq

	if len(data) > 0 {
		if _, err := c.tcpConn.Write(data); err != nil {
			return fmt.Errorf("tunnel: writing to tcp: %w", err)
		}
		c.logger.Debug("forwarded to tcp", "bytes", len(data), "seq", seq)
	}
	return nil
}

// DrainPending returns buffered data from the TCP backend (up to maxBytes)
// and a response packet. This is called when the client sends a NOP or DATA query.
//
// If no data is available yet, it waits up to DrainWait for the readLoop to
// buffer TCP backend data. This simulates the original dns2tcp C server's
// behavior of queuing DNS requests and replying when TCP data arrives.
func (c *Client) DrainPending(ackSeq uint16, maxBytes int) *protocol.Packet {
	c.mu.Lock()

	// If no pending data and connection still alive, wait briefly for TCP data.
	if len(c.pendingData) == 0 && !c.isClosed {
		c.mu.Unlock()
		select {
		case <-c.dataReady:
		case <-time.After(DrainWait):
		}
		c.mu.Lock()
	}
	defer c.mu.Unlock()

	pkt := &protocol.Packet{
		SessionID: c.SessionID,
		AckSeq:    ackSeq,
		Seq:       c.NumSeq,
		Type:      protocol.TypeACK,
	}

	if len(c.pendingData) > 0 {
		n := len(c.pendingData)
		if n > maxBytes {
			n = maxBytes
		}

		pkt.Payload = make([]byte, n)
		copy(pkt.Payload, c.pendingData[:n])
		c.pendingData = c.pendingData[n:]
		pkt.Type = protocol.TypeACK | protocol.TypeData

		c.logger.Debug("draining data", "bytes", n, "remaining", len(c.pendingData))
	} else if c.isClosed {
		pkt.Type = protocol.TypeDesauth
	} else {
		pkt.Type = protocol.TypeACK | protocol.TypeNOP
	}

	c.NumSeq++
	if c.NumSeq == 0 {
		c.NumSeq = 1 // skip zero, same as dns2tcp
	}

	return pkt
}

// Close shuts down the client's TCP connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn != nil && !c.isClosed {
		c.tcpConn.Close()
		c.isClosed = true
	}
}

// IsClosed returns whether the TCP backend connection is closed.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}
