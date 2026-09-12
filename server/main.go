package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/songgao/water"
)

const (
	Magic      = "VTUN"
	Version    = 1
	TypeIP     = 1
	HeaderSize = 8

	TUNIP   = "10.10.0.2"
	TUNPeer = "10.10.0.1"
	TUNMask = "30"
)

func main() {
	// =========================
	// 1. 创建 TUN
	// =========================
	config := water.Config{
		DeviceType: water.TUN,
	}

	tun, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("TUN:", tun.Name())

	// =========================
	// 2. 自动配置 TUN IP
	// =========================
	if err := configureTUN(tun.Name()); err != nil {
		log.Fatal(err)
	}

	// =========================
	// 3. UDP
	// =========================
	addr, err := net.ResolveUDPAddr("udp", ":19000")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("UDP listen:", addr)

	// 保存客户端 UDP 地址
	var (
		clientAddr *net.UDPAddr
		mu         sync.RWMutex
	)

	// =========================
	// 4. TUN -> UDP
	// =========================
	go func() {
		buf := make([]byte, 65535)

		for {
			n, err := tun.Read(buf)
			if err != nil {
				log.Println("TUN read error:", err)
				continue
			}

			packet := buf[:n]

			mu.RLock()
			dst := clientAddr
			mu.RUnlock()

			if dst == nil {
				log.Println("TUN -> UDP: no client")
				continue
			}

			vpnPacket := pack(packet)

			_, err = conn.WriteToUDP(vpnPacket, dst)
			if err != nil {
				log.Println("UDP send error:", err)
				continue
			}

			fmt.Printf(
				"TUN -> UDP: %d bytes -> %s\n",
				n,
				dst,
			)
		}
	}()

	// =========================
	// 5. UDP -> TUN
	// =========================
	buf := make([]byte, 65535)

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP read error:", err)
			continue
		}

		// 记住客户端地址
		mu.Lock()
		clientAddr = addr
		mu.Unlock()

		fmt.Printf(
			"UDP <- %s: %d bytes\n",
			addr,
			n,
		)

		packet, err := unpack(buf[:n])
		if err != nil {
			log.Println("invalid VPN packet:", err)
			continue
		}

		fmt.Printf(
			"UDP -> TUN: %d bytes\n",
			len(packet),
		)

		_, err = tun.Write(packet)
		if err != nil {
			log.Println("TUN write error:", err)
		}
	}
}

// configureTUN 自动配置 TUN IP
func configureTUN(name string) error {
	// 先删除可能存在的旧配置
	_ = exec.Command(
		"ip",
		"addr",
		"flush",
		"dev",
		name,
	).Run()

	// 配置：
	//
	// 10.10.0.2/30
	//
	// 对端：
	// 10.10.0.1
	//
	cmd := exec.Command(
		"ip",
		"addr",
		"add",
		TUNIP+"/"+TUNMask,
		"dev",
		name,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure IP failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	// 启动 TUN
	cmd = exec.Command(
		"ip",
		"link",
		"set",
		"dev",
		name,
		"up",
	)

	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"bring TUN up failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"TUN configured: %s -> %s/%s\n",
		name,
		TUNIP,
		TUNMask,
	)

	return nil
}

// pack:
// VTUN header + IP packet
func pack(packet []byte) []byte {
	vpnPacket := make([]byte, HeaderSize+len(packet))

	copy(vpnPacket[0:4], Magic)

	vpnPacket[4] = Version
	vpnPacket[5] = TypeIP

	binary.BigEndian.PutUint16(
		vpnPacket[6:8],
		uint16(len(packet)),
	)

	copy(vpnPacket[8:], packet)

	return vpnPacket
}

// unpack:
// VTUN header -> IP packet
func unpack(data []byte) ([]byte, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("packet too short")
	}

	if string(data[0:4]) != Magic {
		return nil, fmt.Errorf("invalid magic")
	}

	if data[4] != Version {
		return nil, fmt.Errorf("invalid version")
	}

	if data[5] != TypeIP {
		return nil, fmt.Errorf("invalid type")
	}

	length := int(binary.BigEndian.Uint16(data[6:8]))

	if len(data) < HeaderSize+length {
		return nil, fmt.Errorf(
			"invalid length: header=%d payload=%d",
			len(data),
			length,
		)
	}

	return data[HeaderSize : HeaderSize+length], nil
}
