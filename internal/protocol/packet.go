package protocol

import (
	"encoding/binary"
	"fmt"
)

// HeaderSize is the size of a dns2tcp packet header in bytes.
const HeaderSize = 7

// Packet type flags matching the dns2tcp C implementation.
const (
	TypeOK          uint8 = 0x00
	TypeDesauth     uint8 = 0x01
	TypeErr         uint8 = 0x02
	TypeNOP         uint8 = 0x04
	TypeCheckMTU    uint8 = 0x06
	TypeData        uint8 = 0x08
	TypeACK         uint8 = 0x10
	TypeNACK        uint8 = 0x20
	TypeUseCompress uint8 = 0x40
)

// Packet represents a dns2tcp protocol packet (7-byte header + optional payload).
type Packet struct {
	SessionID uint16
	AckSeq    uint16
	Seq       uint16
	Type      uint8
	Payload   []byte
}

// Marshal serializes the packet into bytes (header + payload).
func (p *Packet) Marshal() []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], p.SessionID)
	binary.BigEndian.PutUint16(buf[2:4], p.AckSeq)
	binary.BigEndian.PutUint16(buf[4:6], p.Seq)
	buf[6] = p.Type
	copy(buf[HeaderSize:], p.Payload)
	return buf
}

// Unmarshal deserializes bytes into a Packet.
func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("protocol: packet too short (%d bytes, need %d)", len(data), HeaderSize)
	}

	p := &Packet{
		SessionID: binary.BigEndian.Uint16(data[0:2]),
		AckSeq:    binary.BigEndian.Uint16(data[2:4]),
		Seq:       binary.BigEndian.Uint16(data[4:6]),
		Type:      data[6],
	}

	if len(data) > HeaderSize {
		p.Payload = make([]byte, len(data)-HeaderSize)
		copy(p.Payload, data[HeaderSize:])
	}

	return p, nil
}

// HasFlag checks if a specific type flag is set.
func (p *Packet) HasFlag(flag uint8) bool {
	return p.Type&flag != 0
}

// IsNOP returns true if this is a poll/keepalive packet.
func (p *Packet) IsNOP() bool {
	return p.Type == TypeNOP
}

// IsData returns true if this packet carries TCP data.
func (p *Packet) IsData() bool {
	return p.HasFlag(TypeData)
}

// IsDesauth returns true if this is a disconnect packet.
func (p *Packet) IsDesauth() bool {
	return p.Type == TypeDesauth
}
