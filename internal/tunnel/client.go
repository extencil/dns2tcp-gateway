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

	MaxPayloadSize = 100 // max raw bytes per DNS response after headers + base64 + overhead
	ReadBufferSize = 4096

	/*
	 * slotExpiry: how long a USED slot waits before NOP reply.
	 * Matches C server's REQUEST_UTIMEOUT = 500ms. Must be shorter than
	 * Cloudflare's retry interval (~500ms) and well under SERVFAIL (~3s).
	 */
	slotExpiry    = 500 * time.Millisecond
	sweepInterval = 100 * time.Millisecond // expiry ticker interval
	DrainWait     = 600 * time.Millisecond // safety-net timeout, sweep should NOP first

	/*
	 * headGracePeriod: delay before first dispatch at session start.
	 * Through public resolvers, queries from the same batch arrive out
	 * of order (higher seq first). This lets the full batch assemble so
	 * finalizeHead can pick the lowest seq. Only applies once.
	 */
	headGracePeriod = 50 * time.Millisecond
)

// slotStatus tracks the lifecycle of a seq slot in the ring.
type slotStatus int

const (
	slotUsed    slotStatus = iota // query registered, waiting for data
	slotReplied                   // response sent, cached for retries
)

/*
 * seqSlot: a DNS query in the seq window, waiting for TCP data or expiry.
 * Lifecycle: USED (query arrives) -> REPLIED (data/NOP dispatched).
 * After head advances past a REPLIED slot, the reply moves to the
 * dispatched cache and the slot is deleted from the ring.
 */
type seqSlot struct {
	status    slotStatus
	seq       uint16
	maxBytes  int
	result    chan *protocol.Packet
	reply     *protocol.Packet
	arrivedAt time.Time
}

/*
 * Client: an authenticated dns2tcp tunnel client.
 *
 * Data flow (mirrors C server architecture):
 *   DNS query -> DrainPending: retry = cached response, new = ring[seq] + inline dispatch
 *   TCP data  -> readLoop buffers -> tryDispatch from head forward
 *   100ms tick -> sweep old USED slots with NOP -> advance head
 *
 * Ring is a map keyed by seq. nextDispatchSeq is the head (lowest seq
 * that gets the next data chunk), matching C server's positional ring.
 */
type Client struct {
	mu        sync.Mutex
	SessionID uint16
	Subdomain string
	Challenge string
	IsAuthed  bool
	authedCh  chan struct{} // closed when IsAuthed becomes true
	Resource  string
	CreatedAt time.Time

	tcpConn     net.Conn
	pendingData []byte
	connecting  bool // guards concurrent ConnectTCP

	ring            map[uint16]*seqSlot    // active query slots by seq
	nextDispatchSeq uint16                 // head: next seq to receive data
	headReady       bool                   // set on first query
	dispatching     bool                   // locked after first data dispatch
	headGraceUntil  time.Time              // initial batch assembly window
	dispatched      map[uint16]*protocol.Packet // evicted reply cache for retries

	stopSweep chan struct{}
	sweepOnce sync.Once

	/* incoming data: buffered by seq, flushed to TCP in order */
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
		CreatedAt:  time.Now(),
		authedCh:   make(chan struct{}),
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

// tryDispatch: dispatch data from head forward. Must hold c.mu.
func (c *Client) tryDispatch() {
	if !c.headReady {
		return
	}

	/* grace period: let initial batch assemble before dispatching */
	if !c.headGraceUntil.IsZero() {
		if time.Now().Before(c.headGraceUntil) {
			return
		}
		// Grace period expired. Finalize head to the lowest seq in ring.
		c.finalizeHead()
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

// replySlot: send packet to slot and mark REPLIED. Must hold c.mu.
func (c *Client) replySlot(slot *seqSlot, pkt *protocol.Packet) {
	slot.reply = pkt
	slot.status = slotReplied
	select {
	case slot.result <- pkt:
	default:
	}
}

// advanceHead: move past REPLIED/missing slots, evict to cache. Must hold c.mu.
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

// finalizeHead: set head to lowest seq in ring after grace period. Must hold c.mu.
func (c *Client) finalizeHead() {
	c.headGraceUntil = time.Time{} // clear grace

	if len(c.ring) == 0 {
		return
	}

	// Find the lowest seq in the ring.
	first := true
	var lowest uint16
	for seq := range c.ring {
		if first || seqBefore(seq, lowest) {
			lowest = seq
			first = false
		}
	}
	c.nextDispatchSeq = lowest
	c.logger.Debug("head finalized", "seq", lowest, "ring_size", len(c.ring))
}

// expirySweep: background NOP for old USED slots (C server's queue_flush_expired_data).
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

// doSweep: expire old USED slots, advance head. Must hold c.mu.
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

	if len(c.dispatched) > QueueSize*2 {
		c.pruneDispatched()
	}
}

func (c *Client) pruneDispatched() {
	for seq := range c.dispatched {
		if seqBefore(seq, c.nextDispatchSeq) {
			diff := c.nextDispatchSeq - seq
			if diff > QueueSize*2 {
				delete(c.dispatched, seq)
			}
		}
	}
}

// makeDataPacket: consume chunk from pendingData. Must hold c.mu.
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

// MarkNOPSeen: record NOP query seq so flushIncoming can skip gaps.
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

// HandleData: buffer incoming client data by seq, flush to TCP in order.
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

// flushIncoming: write buffered data to TCP in seq order. Must hold c.mu.
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

/*
 * DrainPending: register query in seq window, wait for data or expiry NOP.
 * Retries for already-dispatched seqs return cached response immediately.
 */
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

	/* init head with grace period; first arrival may not be lowest seq */
	if !c.headReady {
		c.nextDispatchSeq = clientSeq
		c.headReady = true
		c.headGraceUntil = time.Now().Add(headGracePeriod)
	} else if !c.dispatching && seqBefore(clientSeq, c.nextDispatchSeq) {
		diff := c.nextDispatchSeq - clientSeq
		if diff < QueueSize {
			c.nextDispatchSeq = clientSeq
		}
	}

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

	result := make(chan *protocol.Packet, 1)
	c.ring[clientSeq] = &seqSlot{
		status:    slotUsed,
		seq:       clientSeq,
		maxBytes:  maxBytes,
		result:    result,
		arrivedAt: time.Now(),
	}

	c.tryDispatch()

	c.mu.Unlock()

	select {
	case pkt := <-result:
		return pkt
	case <-time.After(DrainWait):
		/* safety net: sweep should have NOP'd already */
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

// SetAuthed: mark authenticated, unblock WaitAuthed callers.
func (c *Client) SetAuthed() {
	c.mu.Lock()
	c.IsAuthed = true
	c.mu.Unlock()
	close(c.authedCh)
}

// WaitAuthed: block until authenticated or timeout. Returns true if authed.
func (c *Client) WaitAuthed(timeout time.Duration) bool {
	c.mu.Lock()
	if c.IsAuthed {
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()

	select {
	case <-c.authedCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

// IsClosed returns whether the TCP backend connection is closed.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isClosed
}
