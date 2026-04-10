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
	MaxPayloadSize = 100

	// ReadBufferSize is the TCP read buffer size.
	ReadBufferSize = 4096

	// slotExpiry is how long a USED slot waits before getting a NOP reply.
	// The C server uses REQUEST_UTIMEOUT = 500ms. We use 500ms to match.
	// This must be shorter than Cloudflare's retry interval (~500ms) so
	// queries get NOP'd before the resolver retries, and well under the
	// SERVFAIL threshold (~3s).
	slotExpiry = 500 * time.Millisecond

	// sweepInterval is how often the expiry ticker runs.
	sweepInterval = 100 * time.Millisecond

	// DrainWait is the safety-net timeout for DrainPending. The expiry
	// sweep should always NOP a slot before this fires. This is a fallback
	// in case the sweep goroutine is delayed.
	DrainWait = 600 * time.Millisecond

	// flushTrigger: when the gap between nextDispatchSeq and an incoming
	// seq exceeds this, preemptively NOP old USED slots to prevent ring
	// saturation. Matches C server's QUEUE_SIZE/4.
	flushTrigger = QueueSize / 4
)

// slotStatus tracks the lifecycle of a seq slot in the ring.
type slotStatus int

const (
	slotUsed    slotStatus = iota // query registered, waiting for data
	slotReplied                   // response sent, cached for retries
)

// seqSlot represents a DNS query sitting in the seq window, waiting for
// TCP data or expiry. This replaces the old drainSlot + batch sort design.
//
// Lifecycle: USED (query arrives) -> REPLIED (data/NOP dispatched)
// After head advances past a REPLIED slot, the reply moves to the
// dispatched cache and the slot is deleted from the ring.
type seqSlot struct {
	status    slotStatus
	seq       uint16
	maxBytes  int
	result    chan *protocol.Packet
	reply     *protocol.Packet
	arrivedAt time.Time
}

// Client represents an authenticated dns2tcp tunnel client.
//
// Server-to-client data flow (rewritten to match C server architecture):
//
//	DNS query arrives -> DrainPending:
//	  - Retry for replied/evicted seq: return cached response
//	  - New seq: place in ring[seq], try inline dispatch from head
//
//	TCP data arrives -> readLoop buffers in pendingData -> tryDispatch from head
//
//	Expiry sweep (100ms ticker):
//	  - NOP any USED slot older than 500ms (C server's queue_flush_expired_data)
//	  - Advance head past replied/expired slots
//
// The ring is a map keyed by seq number. nextDispatchSeq tracks the head
// (lowest seq that should receive the next data chunk). This mirrors the
// C server's positional ring buffer without needing offset arithmetic.
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Subdomain string
	Challenge string
	IsAuthed  bool
	Resource  string

	// TCP connection to the backend resource.
	tcpConn net.Conn

	// Pending response data read from the TCP backend.
	pendingData []byte

	// Guards against concurrent ConnectTCP calls.
	connecting bool

	// Seq window: active query slots keyed by seq number.
	ring map[uint16]*seqSlot

	// Head of the seq window. Next seq that should receive data.
	// Advances forward as slots are replied and evicted.
	nextDispatchSeq uint16
	headReady       bool // false until first query sets nextDispatchSeq
	dispatching     bool // true after first data dispatch, locks head direction

	// Evicted reply cache: seq -> packet. For Cloudflare retries of seqs
	// that have already been advanced past in the ring.
	dispatched map[uint16]*protocol.Packet

	// Stop signal for expiry sweep goroutine.
	stopSweep chan struct{}
	sweepOnce sync.Once

	// Incoming data queue: client data arrives out of order through DNS
	// resolvers. Buffer by seq and flush to TCP in order.
	incomingBuf   map[uint16][]byte
	nextIncomSeq  uint16
	incomSeqReady bool
	seenSeqs      map[uint16]bool
	flushing      bool

	isClosed bool
	logger   *slog.Logger
}

// NewClient creates a new unauthenticated client with the given session ID.
func NewClient(sessionID uint16, logger *slog.Logger) *Client {
	return &Client{
		SessionID:  sessionID,
		ring:       make(map[uint16]*seqSlot),
		dispatched: make(map[uint16]*protocol.Packet),
		stopSweep:  make(chan struct{}),
		logger:     logger.With("session_id", sessionID),
	}
}

// ConnectTCP opens a TCP connection to the target resource.
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
	c.sweepOnce.Do(func() { go c.expirySweep() })

	return nil
}

// readLoop reads data from the TCP backend and tries to dispatch.
func (c *Client) readLoop() {
	buf := make([]byte, ReadBufferSize)
	for {
		n, err := c.tcpConn.Read(buf)
		if n > 0 {
			c.mu.Lock()
			c.pendingData = append(c.pendingData, buf[:n]...)
			c.tryDispatch()
			c.mu.Unlock()
			c.logger.Debug("tcp data buffered", "bytes", n)
		}
		if err != nil {
			if err != io.EOF {
				c.logger.Debug("tcp read error", "error", err)
			}
			c.mu.Lock()
			c.isClosed = true
			c.tryDispatch()
			c.mu.Unlock()
			c.logger.Info("tcp connection closed")
			return
		}
	}
}

// tryDispatch dispatches pending data to USED slots starting from the head
// (nextDispatchSeq) and cascading forward through consecutive USED slots.
// Must be called with c.mu held.
func (c *Client) tryDispatch() {
	if !c.headReady {
		return
	}

	for {
		slot, ok := c.ring[c.nextDispatchSeq]
		if !ok || slot.status != slotUsed {
			return
		}

		if c.isClosed && len(c.pendingData) == 0 {
			pkt := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       slot.seq,
				Type:      protocol.TypeDesauth,
			}
			c.replySlot(slot, pkt)
			c.advanceHead()
			continue
		}

		if len(c.pendingData) == 0 {
			return
		}

		pkt := c.makeDataPacket(slot.seq, slot.maxBytes)
		c.dispatching = true
		c.replySlot(slot, pkt)
		c.advanceHead()
	}
}

// replySlot sends a packet to the slot's result channel and marks it REPLIED.
// Must be called with c.mu held.
func (c *Client) replySlot(slot *seqSlot, pkt *protocol.Packet) {
	slot.reply = pkt
	slot.status = slotReplied
	select {
	case slot.result <- pkt:
	default:
	}
}

// advanceHead moves nextDispatchSeq past all non-USED slots (REPLIED or
// missing), evicting replied slots to the dispatched cache.
// Must be called with c.mu held.
func (c *Client) advanceHead() {
	for {
		slot, ok := c.ring[c.nextDispatchSeq]
		if !ok {
			// Gap: this seq was never seen (lost query, or already evicted).
			// Only advance if the next seq has a slot, otherwise stop.
			if _, hasNext := c.ring[c.nextDispatchSeq+1]; hasNext {
				c.nextDispatchSeq++
				continue
			}
			return
		}
		if slot.status == slotUsed {
			return // still waiting
		}
		// REPLIED: evict to dispatched cache.
		if slot.reply != nil {
			c.dispatched[c.nextDispatchSeq] = slot.reply
		}
		delete(c.ring, c.nextDispatchSeq)
		c.nextDispatchSeq++
	}
}

// expirySweep runs in a background goroutine. Every sweepInterval (100ms),
// it NOP's any USED slot older than slotExpiry (500ms) and advances the head.
// This matches the C server's queue_flush_expired_data behavior.
func (c *Client) expirySweep() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.doSweep()
			c.mu.Unlock()
		case <-c.stopSweep:
			return
		}
	}
}

// doSweep expires old USED slots and advances the head.
// Must be called with c.mu held.
func (c *Client) doSweep() {
	now := time.Now()
	for seq, slot := range c.ring {
		if slot.status != slotUsed {
			continue
		}
		if now.Sub(slot.arrivedAt) < slotExpiry {
			continue
		}
		nop := &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       seq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
		c.logger.Debug("expiry NOP", "seq", seq, "age_ms", now.Sub(slot.arrivedAt).Milliseconds())
		c.replySlot(slot, nop)
	}
	c.advanceHead()

	// Prune old dispatched cache entries. Keep at most QueueSize*2 entries.
	if len(c.dispatched) > QueueSize*2 {
		c.pruneDispatched()
	}
}

// pruneDispatched removes the oldest entries from the dispatched cache.
// Must be called with c.mu held.
func (c *Client) pruneDispatched() {
	// Find the lowest seq in dispatched and remove entries far behind head.
	for seq := range c.dispatched {
		if seqBefore(seq, c.nextDispatchSeq) {
			diff := c.nextDispatchSeq - seq
			if diff > QueueSize*2 {
				delete(c.dispatched, seq)
			}
		}
	}
}

// flushOldSlots preemptively NOP's USED slots when the seq gap from head
// is too large, preventing ring saturation. Matches C server's FLUSH_TRIGGER.
// Must be called with c.mu held.
func (c *Client) flushOldSlots(incomingSeq uint16) {
	if !c.headReady {
		return
	}
	gap := incomingSeq - c.nextDispatchSeq
	if gap <= flushTrigger {
		return
	}

	// NOP the oldest gap/2 USED slots.
	count := int(gap) / 2
	flushed := 0
	for seq := c.nextDispatchSeq; flushed < count; seq++ {
		slot, ok := c.ring[seq]
		if !ok {
			continue
		}
		if slot.status != slotUsed {
			continue
		}
		nop := &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       seq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
		c.logger.Debug("flush trigger NOP", "seq", seq, "gap", gap)
		c.replySlot(slot, nop)
		flushed++
	}
	c.advanceHead()
}

// makeDataPacket consumes a chunk from pendingData and returns a DATA packet.
// Must be called with c.mu held.
func (c *Client) makeDataPacket(seq uint16, maxBytes int) *protocol.Packet {
	n := len(c.pendingData)
	if n > maxBytes {
		n = maxBytes
	}
	chunk := make([]byte, n)
	copy(chunk, c.pendingData[:n])
	c.pendingData = c.pendingData[n:]

	c.logger.Debug("dispatch data", "seq", seq, "bytes", n, "remaining", len(c.pendingData))

	return &protocol.Packet{
		SessionID: c.SessionID,
		Seq:       seq,
		AckSeq:    0,
		Type:      protocol.TypeACK | protocol.TypeData,
		Payload:   chunk,
	}
}

// MarkNOPSeen records that a NOP query (no payload) with this seq was received.
func (c *Client) MarkNOPSeen(seq uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.seenSeqs == nil {
		c.seenSeqs = make(map[uint16]bool)
	}
	c.seenSeqs[seq] = true

	if !c.incomSeqReady {
		c.nextIncomSeq = seq
		c.incomSeqReady = true
	}
	if !c.flushing && seqBefore(seq, c.nextIncomSeq) {
		c.nextIncomSeq = seq
	}

	if c.tcpConn != nil && !c.isClosed {
		_ = c.flushIncoming()
	}
}

// HandleData buffers incoming client data indexed by seq, then flushes to
// the TCP backend in order.
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

	if c.incomingBuf == nil {
		c.incomingBuf = make(map[uint16][]byte)
	}
	if c.seenSeqs == nil {
		c.seenSeqs = make(map[uint16]bool)
	}

	if c.flushing && c.incomSeqReady && seqBefore(seq, c.nextIncomSeq) {
		c.logger.Debug("seq already flushed, rejecting", "seq", seq, "nextIncomSeq", c.nextIncomSeq)
		return nil
	}

	if c.seenSeqs[seq] {
		c.logger.Debug("duplicate incoming seq, skipping", "seq", seq)
		return nil
	}

	c.seenSeqs[seq] = true
	if !c.incomSeqReady {
		c.nextIncomSeq = seq
		c.incomSeqReady = true
	}
	if !c.flushing && seqBefore(seq, c.nextIncomSeq) {
		c.nextIncomSeq = seq
	}

	buf := make([]byte, len(data))
	copy(buf, data)
	c.incomingBuf[seq] = buf

	return c.flushIncoming()
}

// flushIncoming writes buffered client data to TCP in seq order.
// Must be called with c.mu held.
func (c *Client) flushIncoming() error {
	for {
		if data, ok := c.incomingBuf[c.nextIncomSeq]; ok {
			c.flushing = true
			if _, err := c.tcpConn.Write(data); err != nil {
				return fmt.Errorf("tunnel: writing to tcp: %w", err)
			}
			c.logger.Debug("forwarded to tcp", "bytes", len(data), "seq", c.nextIncomSeq)
			delete(c.incomingBuf, c.nextIncomSeq)
		} else if c.seenSeqs[c.nextIncomSeq] {
			c.logger.Debug("skipping NOP gap", "seq", c.nextIncomSeq)
		} else {
			return nil
		}

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

// DrainPending registers a query in the seq window and waits for the
// dispatcher or expiry sweep to reply. Retries for already-dispatched
// seqs return the cached response immediately.
func (c *Client) DrainPending(clientSeq uint16, maxBytes int) *protocol.Packet {
	c.mu.Lock()

	// Check ring first: retry for a slot still in the window.
	if slot, ok := c.ring[clientSeq]; ok && slot.status == slotReplied {
		c.mu.Unlock()
		c.logger.Debug("replay from ring", "seq", clientSeq)
		return slot.reply
	}

	// Check evicted cache: retry for a seq that advanced past.
	if cached, ok := c.dispatched[clientSeq]; ok {
		c.mu.Unlock()
		c.logger.Debug("replay from cache", "seq", clientSeq)
		return cached
	}

	// TCP closed with no remaining data.
	if c.isClosed && len(c.pendingData) == 0 {
		c.mu.Unlock()
		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			Type:      protocol.TypeDesauth,
		}
	}

	// Initialize head from first query. Adjust downward if a lower seq
	// arrives before the first dispatch (Cloudflare reordering).
	if !c.headReady {
		c.nextDispatchSeq = clientSeq
		c.headReady = true
	} else if !c.dispatching && seqBefore(clientSeq, c.nextDispatchSeq) {
		diff := c.nextDispatchSeq - clientSeq
		if diff < QueueSize {
			c.nextDispatchSeq = clientSeq
		}
	}

	// Reject seqs too far behind head (stale retries not in cache).
	if c.dispatching && seqBefore(clientSeq, c.nextDispatchSeq) {
		c.mu.Unlock()
		c.logger.Debug("stale seq behind head, NOP", "seq", clientSeq, "head", c.nextDispatchSeq)
		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
	}

	// Already have a USED slot for this seq (duplicate arrival before reply).
	if existing, ok := c.ring[clientSeq]; ok && existing.status == slotUsed {
		c.mu.Unlock()
		// Wait on the existing slot's result channel.
		select {
		case pkt := <-existing.result:
			return pkt
		case <-time.After(DrainWait):
			return &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       clientSeq,
				AckSeq:    0,
				Type:      protocol.TypeACK | protocol.TypeNOP,
			}
		}
	}

	// Place new slot in the ring.
	result := make(chan *protocol.Packet, 1)
	c.ring[clientSeq] = &seqSlot{
		status:    slotUsed,
		seq:       clientSeq,
		maxBytes:  maxBytes,
		result:    result,
		arrivedAt: time.Now(),
	}

	// Flush old slots if seq gap is too large.
	c.flushOldSlots(clientSeq)

	// Inline dispatch: if this seq is the head and data is ready, dispatch now.
	c.tryDispatch()

	c.mu.Unlock()

	select {
	case pkt := <-result:
		return pkt
	case <-time.After(DrainWait):
		// Safety net. The expiry sweep should have NOP'd this slot already.
		c.mu.Lock()
		if slot, ok := c.ring[clientSeq]; ok && slot.status == slotUsed {
			nop := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       clientSeq,
				AckSeq:    0,
				Type:      protocol.TypeACK | protocol.TypeNOP,
			}
			c.replySlot(slot, nop)
			c.advanceHead()
		}
		c.mu.Unlock()

		select {
		case pkt := <-result:
			return pkt
		default:
		}

		return &protocol.Packet{
			SessionID: c.SessionID,
			Seq:       clientSeq,
			AckSeq:    0,
			Type:      protocol.TypeACK | protocol.TypeNOP,
		}
	}
}

// Close shuts down the client's TCP connection and stops the sweep.
func (c *Client) Close() {
	c.mu.Lock()
	if c.tcpConn != nil && !c.isClosed {
		c.tcpConn.Close()
		c.isClosed = true
	}
	for seq, slot := range c.ring {
		if slot.status == slotUsed {
			pkt := &protocol.Packet{
				SessionID: c.SessionID,
				Seq:       seq,
				Type:      protocol.TypeDesauth,
			}
			c.replySlot(slot, pkt)
		}
	}
	c.ring = make(map[uint16]*seqSlot)
	c.mu.Unlock()

	select {
	case c.stopSweep <- struct{}{}:
	default:
	}
}

// IsClosed returns whether the TCP backend connection is closed.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}
