package main

import (
	"encoding/binary"
	"net"
)

// IPヘッダー (IPv4)
type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	TotalLength    uint16
	Identification uint16
	FlagsOffset    uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

// TCPヘッダー
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

// TCPフラグ
const (
	FIN = 1 << 0
	SYN = 1 << 1
	RST = 1 << 2
	PSH = 1 << 3
	ACK = 1 << 4
	URG = 1 << 5
)

// IPヘッダーをバイト列に変換
func (h *IPv4Header) Marshal() []byte {
	buf := make([]byte, 20)
	buf[0] = (h.Version << 4) | (h.IHL & 0x0F)
	buf[1] = h.TOS
	binary.BigEndian.PutUint16(buf[2:4], h.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], h.Identification)
	binary.BigEndian.PutUint16(buf[6:8], h.FlagsOffset)
	buf[8] = h.TTL
	buf[9] = h.Protocol
	binary.BigEndian.PutUint16(buf[10:12], h.Checksum)
	copy(buf[12:16], h.SrcIP.To4())
	copy(buf[16:20], h.DstIP.To4())
	return buf
}

// TCPヘッダーをバイト列に変換
func (h *TCPHeader) Marshal() []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], h.AckNum)
	buf[12] = h.DataOffset << 4
	buf[13] = h.Flags
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	binary.BigEndian.PutUint16(buf[16:18], h.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], h.UrgentPtr)
	return buf
}

// TCPヘッダーをパース
func ParseTCPHeader(data []byte) *TCPHeader {
	if len(data) < 20 {
		return nil
	}
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}
}