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
)

// Client represents an authenticated dns2tcp tunnel client.
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Challenge string
	IsAuthed  bool
	Resource  string
	NumSeq    uint16

	// TCP connection to the backend resource.
	tcpConn net.Conn

	// Pending response data read from the TCP backend, waiting to be sent
	// back via DNS responses when the client polls with NOP queries.
	pendingData []byte

	// Tracks whether the TCP connection has been closed.
	isClosed bool

	logger *slog.Logger
}

// NewClient creates a new unauthenticated client with the given session ID.
func NewClient(sessionID uint16, logger *slog.Logger) *Client {
	return &Client{
		SessionID: sessionID,
		NumSeq:    1,
		logger:    logger.With("session_id", sessionID),
	}
}

// ConnectTCP opens a TCP connection to the target resource.
func (c *Client) ConnectTCP(target string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("tunnel: connecting to %s: %w", target, err)
	}

	c.tcpConn = conn
	c.logger.Info("tcp connection established", "target", target)

	// Start background reader that pulls data from the TCP backend.
	go c.readLoop()

	return nil
}

// readLoop reads data from the TCP backend and buffers it for DNS responses.
func (c *Client) readLoop() {
	buf := make([]byte, ReadBufferSize)
	for {
		n, err := c.tcpConn.Read(buf)
		if n > 0 {
			c.mu.Lock()
			c.pendingData = append(c.pendingData, buf[:n]...)
			c.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				c.logger.Debug("tcp read error", "error", err)
			}
			c.mu.Lock()
			c.isClosed = true
			c.mu.Unlock()
			c.logger.Info("tcp connection closed")
			return
		}
	}
}

// HandleData processes incoming TCP data from the client (received via DNS query)
// and writes it to the backend TCP connection.
func (c *Client) HandleData(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn == nil {
		return fmt.Errorf("tunnel: no tcp connection")
	}
	if c.isClosed {
		return fmt.Errorf("tunnel: tcp connection closed")
	}

	if len(data) > 0 {
		if _, err := c.tcpConn.Write(data); err != nil {
			return fmt.Errorf("tunnel: writing to tcp: %w", err)
		}
	}
	return nil
}

// DrainPending returns buffered data from the TCP backend (up to maxBytes)
// and a response packet. This is called when the client sends a NOP or DATA query.
func (c *Client) DrainPending(ackSeq uint16, maxBytes int) *protocol.Packet {
	c.mu.Lock()
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
