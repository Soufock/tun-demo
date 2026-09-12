package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

const (
	Magic      = "VTUN"
	Version    = 1
	TypeIP     = 1
	HeaderSize = 8
	MaxPacket  = 65535

	// =========================
	// VPN 配置
	// =========================

	ClientIP = "10.10.0.1"
	ServerIP = "10.10.0.2"

	// 需要通过 VPN 访问的网段
	VPNNetwork = "10.88.0.0/24"
)

func main() {

	// ============================================================
	// 1. 创建 TUN
	// ============================================================

	config := water.Config{
		DeviceType: water.TUN,
	}

	tun, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()

	fmt.Println("TUN:", tun.Name())

	// ============================================================
	// 2. 自动配置 TUN IP
	// ============================================================

	if err := configureTUN(tun.Name()); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 3. 自动配置 VPN 路由
	// ============================================================

	if err := configureRoute(tun.Name()); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 4. 连接 VPN Server
	// ============================================================

	serverAddr, err := net.ResolveUDPAddr(
		"udp",
		"103.217.197.174:19000",
	)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP(
		"udp",
		nil,
		serverAddr,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("UDP server:", serverAddr)

	// ============================================================
	// 5. TUN -> UDP
	// ============================================================

	go func() {
		buf := make([]byte, MaxPacket)

		for {
			n, err := tun.Read(buf)
			if err != nil {
				log.Fatal("TUN read:", err)
			}

			packet := buf[:n]

			fmt.Printf(
				"TUN -> UDP: IP packet %d bytes\n",
				len(packet),
			)

			vpnPacket := make([]byte, HeaderSize+len(packet))

			copy(vpnPacket[0:4], Magic)

			vpnPacket[4] = Version

			vpnPacket[5] = TypeIP

			binary.BigEndian.PutUint16(
				vpnPacket[6:8],
				uint16(len(packet)),
			)

			copy(
				vpnPacket[HeaderSize:],
				packet,
			)

			_, err = conn.Write(vpnPacket)
			if err != nil {
				log.Fatal("UDP write:", err)
			}
		}
	}()

	// ============================================================
	// 6. UDP -> TUN
	// ============================================================

	buf := make([]byte, MaxPacket+HeaderSize)

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatal("UDP read:", err)
		}

		fmt.Printf(
			"UDP <- %s: %d bytes\n",
			addr,
			n,
		)

		if n < HeaderSize {
			fmt.Println("UDP packet too small")
			continue
		}

		// Magic
		if string(buf[0:4]) != Magic {
			fmt.Printf(
				"Invalid magic: %q\n",
				string(buf[0:4]),
			)
			continue
		}

		// Version
		if buf[4] != Version {
			fmt.Printf(
				"Invalid version: %d\n",
				buf[4],
			)
			continue
		}

		// Type
		if buf[5] != TypeIP {
			fmt.Printf(
				"Unsupported type: %d\n",
				buf[5],
			)
			continue
		}

		// Packet length
		packetLen := int(
			binary.BigEndian.Uint16(
				buf[6:8],
			),
		)

		if packetLen <= 0 {
			fmt.Println("Invalid packet length")
			continue
		}

		if HeaderSize+packetLen > n {
			fmt.Printf(
				"Packet length mismatch: packet=%d udp=%d\n",
				packetLen,
				n,
			)
			continue
		}

		// 提取 IP Packet
		packet := buf[HeaderSize : HeaderSize+packetLen]

		if len(packet) >= 20 {
			srcIP := net.IP(packet[12:16])
			dstIP := net.IP(packet[16:20])

			fmt.Printf(
				"UDP -> TUN: %s -> %s, protocol=%d, len=%d\n",
				srcIP,
				dstIP,
				packet[9],
				len(packet),
			)
		} else {
			fmt.Printf(
				"UDP -> TUN: invalid IP packet, len=%d\n",
				len(packet),
			)
			continue
		}

		_, err = tun.Write(packet)
		if err != nil {
			log.Fatal("TUN write:", err)
		}
	}
}

// ============================================================
// 自动配置 TUN
// ============================================================

func configureTUN(tunName string) error {

	fmt.Printf(
		"Configuring TUN %s...\n",
		tunName,
	)

	// macOS：
	//
	// ifconfig utun4 10.10.0.1 10.10.0.2
	//
	cmd := exec.Command(
		"ifconfig",
		tunName,
		ClientIP,
		ServerIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"configure TUN failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"TUN configured: %s -> %s -> %s\n",
		tunName,
		ClientIP,
		ServerIP,
	)

	return nil
}

// ============================================================
// 自动配置路由
// ============================================================

func configureRoute(tunName string) error {

	fmt.Printf(
		"Adding route %s via %s...\n",
		VPNNetwork,
		ServerIP,
	)

	// 防止重复添加导致程序报错
	//
	// route -n get 192.168.0.1
	//
	check := exec.Command(
		"route",
		"-n",
		"get",
		"192.168.0.1",
	)

	if check.Run() == nil {
		fmt.Println("Route already exists, deleting...")

		delCmd := exec.Command(
			"route",
			"delete",
			VPNNetwork,
		)

		output, err := delCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf(
				"delete route failed: %v: %s",
				err,
				strings.TrimSpace(string(output)),
			)
		}

		fmt.Println("Old route deleted.")
	}
	// macOS：
	//
	// route add 192.168.0.0/24 10.10.0.2
	//
	cmd := exec.Command(
		"route",
		"add",
		VPNNetwork,
		ServerIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {

		// 已经存在也算正常
		if strings.Contains(
			string(output),
			"File exists",
		) {
			fmt.Println(
				"Route already exists.",
			)
			return nil
		}

		return fmt.Errorf(
			"add route failed: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	fmt.Printf(
		"Route added: %s -> %s\n",
		VPNNetwork,
		ServerIP,
	)

	return nil
}
