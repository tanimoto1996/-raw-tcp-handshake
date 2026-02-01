package main

import (
	"encoding/binary"
	"net"
)

// IPチェックサム計算
func calculateIPChecksum(header []byte) uint16 {
	header[10] = 0
	header[11] = 0
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TCPチェックサム計算
func calculateTCPChecksum(srcIP, dstIP net.IP, tcpHeader, data []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6
	tcpLength := uint16(len(tcpHeader) + len(data))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLength)

	tcpHeader[16] = 0
	tcpHeader[17] = 0

	var sum uint32
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}
	for i := 0; i < len(tcpHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpHeader[i : i+2]))
	}
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}