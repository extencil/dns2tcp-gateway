package protocol

import (
	"testing"
)

func TestPacketMarshalUnmarshal(t *testing.T) {
	pkt := &Packet{
		SessionID: 0x1234,
		AckSeq:    0x0001,
		Seq:       0x0002,
		Type:      TypeData | TypeACK,
		Payload:   []byte("hello"),
	}

	data := pkt.Marshal()
	if len(data) != HeaderSize+5 {
		t.Fatalf("marshal size = %d, want %d", len(data), HeaderSize+5)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.SessionID != pkt.SessionID {
		t.Errorf("session_id = %d, want %d", got.SessionID, pkt.SessionID)
	}
	if got.AckSeq != pkt.AckSeq {
		t.Errorf("ack_seq = %d, want %d", got.AckSeq, pkt.AckSeq)
	}
	if got.Seq != pkt.Seq {
		t.Errorf("seq = %d, want %d", got.Seq, pkt.Seq)
	}
	if got.Type != pkt.Type {
		t.Errorf("type = %d, want %d", got.Type, pkt.Type)
	}
	if string(got.Payload) != "hello" {
		t.Errorf("payload = %q, want %q", got.Payload, "hello")
	}
}

func TestPacketFlags(t *testing.T) {
	pkt := &Packet{Type: TypeData | TypeACK}

	if !pkt.IsData() {
		t.Error("expected IsData() = true")
	}
	if !pkt.HasFlag(TypeACK) {
		t.Error("expected HasFlag(TypeACK) = true")
	}
	if pkt.IsNOP() {
		t.Error("expected IsNOP() = false")
	}

	nop := &Packet{Type: TypeNOP}
	if !nop.IsNOP() {
		t.Error("expected IsNOP() = true")
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	_, err := Unmarshal([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for short packet")
	}
}

func TestPacketHeaderOnly(t *testing.T) {
	pkt := &Packet{
		SessionID: 1,
		Type:      TypeNOP,
	}

	data := pkt.Marshal()
	if len(data) != HeaderSize {
		t.Fatalf("header-only marshal size = %d, want %d", len(data), HeaderSize)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got.Payload))
	}
}
