package main

import (
	"encoding/hex"
	"fmt"
	"net"
)

func main() {
	fmt.Println("=== TCP/IPパケット構築テスト ===\n")

	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("93.184.216.34")
	srcPort := uint16(54321)
	dstPort := uint16(80)
	seqNum := uint32(1000)

	fmt.Println("設定:")
	fmt.Printf("  送信元: %s:%d\n", srcIP, srcPort)
	fmt.Printf("  送信先: %s:%d\n", dstIP, dstPort)
	fmt.Printf("  シーケンス番号: %d\n\n", seqNum)

	// TCPヘッダー構築
	fmt.Println("--- TCPヘッダー ---")
	tcpHeader := &TCPHeader{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     0,
		DataOffset: 5,
		Flags:      SYN,
		Window:     65535,
		Checksum:   0,
		UrgentPtr:  0,
	}

	tcpBytes := tcpHeader.Marshal()
	fmt.Printf("サイズ: %d バイト\n", len(tcpBytes))
	fmt.Println("内容:")
	fmt.Println(hex.Dump(tcpBytes))

	checksum := calculateTCPChecksum(srcIP, dstIP, tcpBytes, nil)
	fmt.Printf("チェックサム: 0x%04x\n\n", checksum)

	// パーステスト
	fmt.Println("--- パーステスト ---")
	parsed := ParseTCPHeader(tcpBytes)
	if parsed != nil {
		fmt.Println("✓ TCPヘッダーのパースに成功")
		fmt.Printf("  送信元ポート: %d\n", parsed.SrcPort)
		fmt.Printf("  送信先ポート: %d\n", parsed.DstPort)
		fmt.Printf("  シーケンス番号: %d\n", parsed.SeqNum)
		fmt.Printf("  フラグ: 0x%02x", parsed.Flags)
		
		flags := []string{}
		if parsed.Flags&SYN != 0 { flags = append(flags, "SYN") }
		if parsed.Flags&ACK != 0 { flags = append(flags, "ACK") }
		if len(flags) > 0 {
			fmt.Printf(" (%v)", flags)
		}
		fmt.Println()
	}

	fmt.Println("\n✓ すべてのテスト完了!")
}
