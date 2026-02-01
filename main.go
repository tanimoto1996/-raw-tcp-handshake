package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("使い方: sudo go run main.go headers.go checksum.go <送信先IP> <送信先ポート>")
		fmt.Println("例: sudo go run main.go headers.go checksum.go 93.184.216.34 80")
		os.Exit(1)
	}

	dstIP := net.ParseIP(os.Args[1])
	if dstIP == nil {
		log.Fatal("無効なIPアドレス")
	}

	var dstPort uint16
	fmt.Sscanf(os.Args[2], "%d", &dstPort)

	fmt.Printf("🚀 TCP 3-way handshake開始: %s:%d\n", dstIP, dstPort)

	// ローカルIPアドレスを取得
	srcIP := getLocalIP()
	if srcIP == nil {
		log.Fatal("ローカルIPアドレスの取得に失敗")
	}
	fmt.Printf("送信元IP: %s\n", srcIP)

	// ランダムな送信元ポート
	rand.Seed(time.Now().UnixNano())
	srcPort := uint16(rand.Intn(65535-1024) + 1024)
	fmt.Printf("送信元ポート: %d\n", srcPort)

	// ステップ1: SYNパケットを送信
	fmt.Println("\n[ステップ1] SYNパケット送信...")
	seqNum := rand.Uint32()
	fmt.Printf("初期シーケンス番号: %d\n", seqNum)

	err := sendSYN(srcIP, dstIP, srcPort, dstPort, seqNum)
	if err != nil {
		log.Fatalf("SYN送信エラー: %v", err)
	}
	fmt.Println("✓ SYNパケット送信完了")

	// ステップ2: SYN-ACKを受信
	fmt.Println("\n[ステップ2] SYN-ACK待機中...")
	synAckHeader, err := receiveSYNACK(srcIP, dstIP, srcPort, dstPort, 5*time.Second)
	if err != nil {
		log.Fatalf("SYN-ACK受信エラー: %v", err)
	}
	fmt.Printf("✓ SYN-ACK受信完了\n")
	fmt.Printf("  サーバーシーケンス番号: %d\n", synAckHeader.SeqNum)
	fmt.Printf("  確認応答番号: %d (期待値: %d)\n", synAckHeader.AckNum, seqNum+1)

	// ステップ3: ACKを送信
	fmt.Println("\n[ステップ3] ACKパケット送信...")
	err = sendACK(srcIP, dstIP, srcPort, dstPort, seqNum+1, synAckHeader.SeqNum+1)
	if err != nil {
		log.Fatalf("ACK送信エラー: %v", err)
	}
	fmt.Println("✓ ACKパケット送信完了")

	fmt.Println("\n🎉 TCP 3-way handshake 完了!")
	fmt.Println("\n接続が確立されました。")
	fmt.Printf("  ローカル: %s:%d\n", srcIP, srcPort)
	fmt.Printf("  リモート: %s:%d\n", dstIP, dstPort)
}

// SYNパケットを送信
func sendSYN(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum uint32) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket作成エラー: %v", err)
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("setsockoptエラー: %v", err)
	}

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
	checksum := calculateTCPChecksum(srcIP, dstIP, tcpBytes, nil)
	tcpHeader.Checksum = checksum
	tcpBytes = tcpHeader.Marshal()

	ipHeader := &IPv4Header{
		Version:        4,
		IHL:            5,
		TOS:            0,
		TotalLength:    uint16(20 + len(tcpBytes)),
		Identification: uint16(rand.Intn(65535)),
		FlagsOffset:    0,
		TTL:            64,
		Protocol:       6,
		Checksum:       0,
		SrcIP:          srcIP,
		DstIP:          dstIP,
	}

	ipBytes := ipHeader.Marshal()
	ipChecksum := calculateIPChecksum(ipBytes)
	binary.BigEndian.PutUint16(ipBytes[10:12], ipChecksum)

	packet := append(ipBytes, tcpBytes...)

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dstIP.To4())

	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("sendtoエラー: %v", err)
	}

	return nil
}

// SYN-ACKを受信 (デバッグ版)
func receiveSYNACK(srcIP, dstIP net.IP, srcPort, dstPort uint16, timeout time.Duration) (*TCPHeader, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("socket作成エラー: %v", err)
	}
	defer syscall.Close(fd)

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err != nil {
		return nil, fmt.Errorf("タイムアウト設定エラー: %v", err)
	}

	buffer := make([]byte, 4096)
	deadline := time.Now().Add(timeout)
	packetCount := 0
	debugCount := 0

	fmt.Println("  パケット受信中...")
	fmt.Printf("  探しているパケット: %s:%d -> %s:%d (SYN+ACK)\n", dstIP, dstPort, srcIP, srcPort)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("recvfromエラー: %v", err)
		}

		packetCount++
		if n < 40 {
			continue
		}

		// IPヘッダーから送信元/送信先IPを取得
		ipSrcIP := net.IP(buffer[12:16])
		ipDstIP := net.IP(buffer[16:20])

		tcpData := buffer[20:n]
		tcpHeader := ParseTCPHeader(tcpData)
		if tcpHeader == nil {
			continue
		}

		// 最初の10パケットだけデバッグ表示
		if debugCount < 10 {
			fmt.Printf("    [%d] %s:%d -> %s:%d, Flags=0x%02x",
				packetCount,
				ipSrcIP, tcpHeader.SrcPort,
				ipDstIP, tcpHeader.DstPort,
				tcpHeader.Flags)

			flags := []string{}
			if tcpHeader.Flags&SYN != 0 {
				flags = append(flags, "SYN")
			}
			if tcpHeader.Flags&ACK != 0 {
				flags = append(flags, "ACK")
			}
			if tcpHeader.Flags&FIN != 0 {
				flags = append(flags, "FIN")
			}
			if tcpHeader.Flags&RST != 0 {
				flags = append(flags, "RST")
			}
			if len(flags) > 0 {
				fmt.Printf(" (%v)", flags)
			}
			fmt.Println()
			debugCount++
		}

		// 自分宛てのSYN-ACKかチェック
		if tcpHeader.DstPort == srcPort &&
			tcpHeader.SrcPort == dstPort &&
			ipSrcIP.Equal(dstIP) &&
			tcpHeader.Flags == (SYN|ACK) {
			fmt.Printf("\n  ✓ SYN-ACKを発見! (%dパケット目)\n", packetCount)
			return tcpHeader, nil
		}
	}

	return nil, fmt.Errorf("タイムアウト: SYN-ACKを受信できませんでした (%dパケット受信)", packetCount)
}

// ACKパケットを送信
func sendACK(srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("socket作成エラー: %v", err)
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("setsockoptエラー: %v", err)
	}

	tcpHeader := &TCPHeader{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: 5,
		Flags:      ACK,
		Window:     65535,
		Checksum:   0,
		UrgentPtr:  0,
	}

	tcpBytes := tcpHeader.Marshal()
	checksum := calculateTCPChecksum(srcIP, dstIP, tcpBytes, nil)
	tcpHeader.Checksum = checksum
	tcpBytes = tcpHeader.Marshal()

	ipHeader := &IPv4Header{
		Version:        4,
		IHL:            5,
		TOS:            0,
		TotalLength:    uint16(20 + len(tcpBytes)),
		Identification: uint16(rand.Intn(65535)),
		FlagsOffset:    0,
		TTL:            64,
		Protocol:       6,
		Checksum:       0,
		SrcIP:          srcIP,
		DstIP:          dstIP,
	}

	ipBytes := ipHeader.Marshal()
	ipChecksum := calculateIPChecksum(ipBytes)
	binary.BigEndian.PutUint16(ipBytes[10:12], ipChecksum)

	packet := append(ipBytes, tcpBytes...)

	addr := syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dstIP.To4())

	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("sendtoエラー: %v", err)
	}

	return nil
}

// ローカルIPアドレスを取得
func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}