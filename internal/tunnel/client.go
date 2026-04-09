package tunnel

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
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

	// DrainWait is how long DrainPending waits for its response from the
	// dispatcher before returning NOP. Keep well under resolver retry timeout.
	DrainWait = 300 * time.Millisecond

	// dispatchInterval is how often the dispatcher checks for pending queries
	// and data to match them up.
	dispatchInterval = 10 * time.Millisecond
)

// drainSlot represents a pending DNS query waiting for TCP backend data.
type drainSlot struct {
	seq      uint16
	maxBytes int
	result   chan *protocol.Packet
}

// Client represents an authenticated dns2tcp tunnel client.
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Subdomain string
	Challenge string
	IsAuthed  bool
	Resource  string

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

	// Incoming data queue: client data arrives out of order through DNS
	// resolvers. Buffer by seq and flush to TCP in order, matching the
	// original dns2tcp server's queue_flush_incoming_data behavior.
	incomingBuf   map[uint16][]byte // seq -> data, waiting to be flushed
	nextIncomSeq  uint16            // next seq to flush to TCP
	incomSeqReady bool              // whether nextIncomSeq has been set

	// Ordered dispatch: DNS handler goroutines register slots here.
	// The dispatcher assigns data to slots sorted by seq (lowest first),
	// matching the original dns2tcp C server's queue behavior.
	slotsMu sync.Mutex
	slots   []drainSlot

	// Tracks whether the TCP connection has been closed.
	isClosed bool

	// Tracks whether the dispatcher goroutine is running.
	dispatchOnce sync.Once
	stopDispatch chan struct{}

	logger *slog.Logger
}

// NewClient creates a new unauthenticated client with the given session ID.
func NewClient(sessionID uint16, logger *slog.Logger) *Client {
	return &Client{
		SessionID:    sessionID,
		dataReady:    make(chan struct{}, 1),
		stopDispatch: make(chan struct{}),
		logger:       logger.With("session_id", sessionID),
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

	go c.readLoop()
	c.dispatchOnce.Do(func() { go c.dispatcher() })

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

// signalDataReady wakes the dispatcher.
func (c *Client) signalDataReady() {
	select {
	case c.dataReady <- struct{}{}:
	default:
	}
}

// HandleData buffers incoming client data (received via DNS query) indexed by
// seq, then flushes to the TCP backend in order. This handles out-of-order
// query arrival through DNS resolvers, matching the original dns2tcp server's
// queue_flush_incoming_data behavior.
func (c *Client) HandleData(seq uint16, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn == nil {
		return fmt.Errorf("tunnel: no tcp connection")
	}
	if c.isClosed {
		return fmt.Errorf("tunnel: tcp connection closed")
	}

	if len(data) == 0 {
		return nil
	}

	// Initialize incoming queue on first data.
	if c.incomingBuf == nil {
		c.incomingBuf = make(map[uint16][]byte)
	}

	// Deduplicate: resolver retries send the same query (same seq) again.
	if _, dup := c.incomingBuf[seq]; dup {
		c.logger.Debug("duplicate incoming seq, skipping", "seq", seq)
		return nil
	}

	// Buffer this seq's data.
	buf := make([]byte, len(data))
	copy(buf, data)
	c.incomingBuf[seq] = buf

	// Set base seq on first data query.
	if !c.incomSeqReady {
		c.nextIncomSeq = seq
		c.incomSeqReady = true
	}
	// Update base if we see a lower seq (earlier packet arrived late).
	if seqBefore(seq, c.nextIncomSeq) {
		c.nextIncomSeq = seq
	}

	// Flush consecutive data to TCP in order.
	return c.flushIncoming()
}

// flushIncoming writes buffered client data to TCP in seq order.
// Must be called with c.mu held.
func (c *Client) flushIncoming() error {
	for {
		data, ok := c.incomingBuf[c.nextIncomSeq]
		if !ok {
			return nil
		}

		if _, err := c.tcpConn.Write(data); err != nil {
			return fmt.Errorf("tunnel: writing to tcp: %w", err)
		}
		c.logger.Debug("forwarded to tcp", "bytes", len(data), "seq", c.nextIncomSeq)

		delete(c.incomingBuf, c.nextIncomSeq)
		c.nextIncomSeq++
		if c.nextIncomSeq == 0 {
			c.nextIncomSeq = 1
		}
	}
}

// seqBefore returns true if a comes before b in the uint16 sequence space.
func seqBefore(a, b uint16) bool {
	return int16(a-b) < 0
}

// DrainPending registers a pending query slot and waits for the dispatcher to
// assign data. The dispatcher processes slots in seq order (lowest first),
// ensuring data chunks are mapped to the correct query slots for the client
// to reassemble in the right order.
func (c *Client) DrainPending(clientSeq uint16, maxBytes int) *protocol.Packet {
	result := make(chan *protocol.Packet, 1)

	c.slotsMu.Lock()
	c.slots = append(c.slots, drainSlot{
		seq:      clientSeq,
		maxBytes: maxBytes,
		result:   result,
	})
	c.slotsMu.Unlock()

	// Wake dispatcher to process this slot.
	c.signalDataReady()

	select {
	case pkt := <-result:
		return pkt
	case <-time.After(DrainWait):
		// Timeout: remove our slot and return NOP.
		c.removeSlot(clientSeq)
		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
	}
}

// removeSlot removes a timed-out slot from the pending list.
func (c *Client) removeSlot(seq uint16) {
	c.slotsMu.Lock()
	defer c.slotsMu.Unlock()
	for i, s := range c.slots {
		if s.seq == seq {
			c.slots = append(c.slots[:i], c.slots[i+1:]...)
			return
		}
	}
}

// dispatcher runs in a background goroutine, matching pending data to
// waiting query slots in seq order. This is the Go equivalent of the
// original dns2tcp C server's queue_read_tcp + queue_reply system.
func (c *Client) dispatcher() {
	for {
		select {
		case <-c.dataReady:
		case <-time.After(dispatchInterval):
		case <-c.stopDispatch:
			return
		}

		c.slotsMu.Lock()
		nSlots := len(c.slots)
		c.slotsMu.Unlock()

		c.mu.Lock()
		hasData := len(c.pendingData) > 0 || c.isClosed
		c.mu.Unlock()

		if hasData && nSlots > 0 {
			// Batch delay: wait for more queries to arrive through DNS
			// resolvers before sorting and dispatching. dns2tcpc sends
			// parallel queries that trickle in over ~5-20ms via Cloudflare.
			// We need all queries in the batch registered before we can
			// sort by seq and assign data to the correct slots.
			time.Sleep(50 * time.Millisecond)
		}

		c.dispatchPending()
	}
}

// dispatchPending assigns data chunks to waiting slots, lowest seq first.
func (c *Client) dispatchPending() {
	c.slotsMu.Lock()
	defer c.slotsMu.Unlock()

	if len(c.slots) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	hasData := len(c.pendingData) > 0
	closed := c.isClosed

	if !hasData && !closed {
		return
	}

	// Sort by seq so data goes to the lowest seq first.
	sort.Slice(c.slots, func(i, j int) bool {
		return c.slots[i].seq < c.slots[j].seq
	})

	var remaining []drainSlot
	for _, slot := range c.slots {
		pkt := &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       slot.seq,
			AckSeq:    0,
			Type:      protocol.TypeACK,
		}

		if len(c.pendingData) > 0 {
			n := len(c.pendingData)
			if n > slot.maxBytes {
				n = slot.maxBytes
			}
			pkt.Payload = make([]byte, n)
			copy(pkt.Payload, c.pendingData[:n])
			c.pendingData = c.pendingData[n:]
			pkt.Type = protocol.TypeACK | protocol.TypeData

			c.logger.Debug("dispatch data", "seq", slot.seq, "bytes", n, "remaining", len(c.pendingData))
		} else if closed {
			pkt.Type = protocol.TypeDesauth
		} else {
			// No more data for remaining slots; keep them waiting.
			remaining = append(remaining, slot)
			continue
		}

		select {
		case slot.result <- pkt:
		default:
		}
	}

	c.slots = remaining
}

// Close shuts down the client's TCP connection and dispatcher.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tcpConn != nil && !c.isClosed {
		c.tcpConn.Close()
		c.isClosed = true
	}

	select {
	case c.stopDispatch <- struct{}{}:
	default:
	}
}

// IsClosed returns whether the TCP backend connection is closed.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}
