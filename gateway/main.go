package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/songgao/water"

	"tun-demo/protocol"
)

const (

	// ============================================================
	// Center
	// ============================================================

	// 部署时修改为真实的 Center 公网地址
	CenterAddr = "103.217.197.174:19000"

	// ============================================================
	// Gateway 注册信息
	// ============================================================

	GatewayID = "company-a"
	AuthToken = "123456"

	// 本 Gateway 接入的公司内网网段
	Networks = "192.168.0.0/24"

	// ============================================================
	// TUN
	// ============================================================

	TUNIP   = "10.10.0.2"
	TUNMask = "24"
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
		log.Fatal("create TUN:", err)
	}

	defer tun.Close()

	fmt.Println("TUN:", tun.Name())

	// ============================================================
	// 2. 配置 TUN
	// ============================================================

	if err := configureTUN(tun.Name()); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 3. 连接 Center
	// ============================================================

	centerAddr, err := net.ResolveUDPAddr(
		"udp",
		CenterAddr,
	)
	if err != nil {
		log.Fatal("resolve center:", err)
	}

	conn, err := net.DialUDP(
		"udp",
		nil,
		centerAddr,
	)
	if err != nil {
		log.Fatal("connect center:", err)
	}

	defer conn.Close()

	fmt.Println(
		"UDP center:",
		centerAddr,
	)

	// ============================================================
	// 4. GATEWAY AUTH
	// ============================================================

	if err := authenticate(conn); err != nil {
		log.Fatal("gateway authentication failed:", err)
	}

	// ============================================================
	// 5. TUN -> UDP
	// ============================================================

	go tunToUDP(
		tun,
		conn,
	)

	// ============================================================
	// 6. UDP -> TUN
	// ============================================================

	udpToTUN(
		tun,
		conn,
	)
}

// ============================================================
// GATEWAY AUTH
//
// Gateway:
//
//     GATEWAY_AUTH + JSON
//
// Center:
//
//     GATEWAY_AUTH_OK
//
// ============================================================

func authenticate(conn *net.UDPConn) error {

	fmt.Println("Authenticating gateway...")

	auth := &protocol.GatewayAuth{
		GatewayID: GatewayID,
		Token:     AuthToken,
		Networks: []string{
			Networks,
		},
	}

	payload, err := protocol.MarshalGatewayAuth(auth)
	if err != nil {
		return fmt.Errorf(
			"marshal gateway auth failed: %w",
			err,
		)
	}

	authPacket := protocol.Pack(
		protocol.TypeGatewayAuth,
		0,
		0,
		payload,
	)

	_, err = conn.Write(authPacket)
	if err != nil {
		return fmt.Errorf(
			"send GATEWAY_AUTH failed: %w",
			err,
		)
	}

	fmt.Println("GATEWAY_AUTH sent")

	// ============================================================
	// 等待 GATEWAY_AUTH_OK
	// ============================================================

	buf := make(
		[]byte,
		4096,
	)

	// 10 秒超时
	if err := conn.SetReadDeadline(
		time.Now().Add(10 * time.Second),
	); err != nil {
		return fmt.Errorf(
			"set auth timeout: %w",
			err,
		)
	}

	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf(
			"read GATEWAY_AUTH response failed: %w",
			err,
		)
	}

	header, payload, err := protocol.Unpack(
		buf[:n],
	)
	if err != nil {
		return fmt.Errorf(
			"invalid GATEWAY_AUTH response: %w",
			err,
		)
	}

	if header.Type == protocol.TypeGatewayAuthFail {

		return fmt.Errorf(
			"center rejected gateway authentication: %s",
			string(payload),
		)
	}

	if header.Type != protocol.TypeGatewayAuthOK {

		return fmt.Errorf(
			"unexpected GATEWAY_AUTH response type: %d",
			header.Type,
		)
	}

	// 恢复正常读取
	if err := conn.SetReadDeadline(
		time.Time{},
	); err != nil {
		return fmt.Errorf(
			"clear read deadline: %w",
			err,
		)
	}

	fmt.Println()
	fmt.Println("==============================")
	fmt.Println("Gateway authentication successful")
	fmt.Println("==============================")
	fmt.Println(
		"GatewayID:",
		GatewayID,
	)
	fmt.Println(
		"Networks:",
		Networks,
	)
	fmt.Println()

	return nil
}

// ============================================================
// TUN -> UDP
// ============================================================

func tunToUDP(
	tun *water.Interface,
	conn *net.UDPConn,
) {

	buf := make(
		[]byte,
		protocol.MaxPacket,
	)

	for {

		// ========================================================
		// 从 TUN 读取 IP Packet
		// ========================================================

		n, err := tun.Read(buf)
		if err != nil {
			log.Println(
				"TUN read error:",
				err,
			)
			continue
		}

		if n <= 0 {
			continue
		}

		packet := buf[:n]

		if len(packet) < 20 {
			log.Println(
				"TUN packet too small:",
				len(packet),
			)
			continue
		}

		srcIP := net.IP(
			packet[12:16],
		)

		dstIP := net.IP(
			packet[16:20],
		)

		fmt.Printf(
			"TUN -> UDP: %s -> %s, protocol=%d, len=%d\n",
			srcIP,
			dstIP,
			packet[9],
			len(packet),
		)

		// ========================================================
		// VTUN 封装
		// ========================================================

		vpnPacket := protocol.Pack(
			protocol.TypeIP,
			0,
			0,
			packet,
		)

		// ========================================================
		// UDP 发送到 Center
		// ========================================================

		_, err = conn.Write(
			vpnPacket,
		)
		if err != nil {
			log.Println(
				"UDP write error:",
				err,
			)
			continue
		}
	}
}

// ============================================================
// UDP -> TUN
// ============================================================

func udpToTUN(
	tun *water.Interface,
	conn *net.UDPConn,
) {

	buf := make(
		[]byte,
		protocol.MaxPacket+protocol.HeaderSize,
	)

	for {

		// ========================================================
		// UDP 接收
		// ========================================================

		n, err := conn.Read(buf)
		if err != nil {
			log.Println(
				"UDP read error:",
				err,
			)
			continue
		}

		// ========================================================
		// 解包
		// ========================================================

		header, packet, err := protocol.Unpack(
			buf[:n],
		)
		if err != nil {
			log.Println(
				"invalid VPN packet:",
				err,
			)
			continue
		}

		if header.Type != protocol.TypeIP {

			fmt.Printf(
				"ignore packet type=%d\n",
				header.Type,
			)

			continue
		}

		if len(packet) < 20 {

			fmt.Printf(
				"invalid IP packet: len=%d\n",
				len(packet),
			)

			continue
		}

		srcIP := net.IP(
			packet[12:16],
		)

		dstIP := net.IP(
			packet[16:20],
		)

		fmt.Printf(
			"UDP -> TUN: %s -> %s, protocol=%d, len=%d\n",
			srcIP,
			dstIP,
			packet[9],
			len(packet),
		)

		// ========================================================
		// 写入 TUN，由内核送入公司内网
		// ========================================================

		_, err = tun.Write(packet)
		if err != nil {
			log.Println(
				"TUN write error:",
				err,
			)
		}
	}
}

// ============================================================
// 平台相关接口
//
// configureTUN 由各平台文件实现：
//
//     configureTUN(name string) error
//
//     name: TUN 设备名（Linux 为 tun0，macOS 为 utunX，Windows 为适配器名）
//
// 各平台实现：
//
//     tun_linux.go    - Linux（ip addr / ip link）
//     tun_darwin.go   - macOS（ifconfig 点对点 + route）
//     tun_windows.go  - Windows（netsh，依赖 TAP-Windows 驱动）
//
// ============================================================
