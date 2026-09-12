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

	// 鉴权 Token
	//
	// 现在先简单使用固定 Token。
	// 后面可以换成真正的用户 Token / JWT / API Key。
	AuthToken = "123456"

	// ============================================================
	// VPN
	// ============================================================

	// Gateway 的 TUN 虚拟地址
	//
	// 作为 macOS 点对点 TUN 的对端地址和路由下一跳：
	//
	//     10.10.0.2
	//
	GatewayIP = "10.10.0.2"

	// 需要通过 VPN 访问的公司网段
	//
	// 例如：
	//
	// 192.168.0.0/24
	//
	VPNNetwork = "192.168.0.0/24"
)

// ============================================================
// 动态获取的 Session 信息
// ============================================================

var (
	// Center 分配
	SessionID uint32

	// Center 分配
	ClientIP string
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
	// 2. 连接 Center
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
	// 3. AUTH
	// ============================================================

	if err := authenticate(conn); err != nil {
		log.Fatal("authentication failed:", err)
	}

	// ============================================================
	// 4. 自动配置 TUN
	// ============================================================

	if err := configureTUN(
		tun.Name(),
		ClientIP,
		GatewayIP,
	); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 5. 自动配置公司网段路由
	// ============================================================

	if err := configureRoute(
		VPNNetwork,
		GatewayIP,
	); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 6. TUN -> UDP
	// ============================================================

	go tunToUDP(
		tun,
		conn,
	)

	// ============================================================
	// 7. UDP -> TUN
	// ============================================================

	udpToTUN(
		tun,
		conn,
	)
}

// ============================================================
// AUTH
//
// Client:
//
//     AUTH + Token
//
// Center:
//
//     AUTH_OK
//     SessionID
//     VPN IP
//
// ============================================================

func authenticate(conn *net.UDPConn) error {

	fmt.Println("Authenticating...")

	// ============================================================
	// 构造 AUTH
	// ============================================================

	authPacket := protocol.Pack(
		protocol.TypeAuth,
		0,
		0,
		[]byte(AuthToken),
	)

	_, err := conn.Write(authPacket)
	if err != nil {
		return fmt.Errorf(
			"send AUTH failed: %w",
			err,
		)
	}

	fmt.Println("AUTH sent")

	// ============================================================
	// 等待 AUTH_OK
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
			"read AUTH response failed: %w",
			err,
		)
	}

	header, payload, err := protocol.Unpack(
		buf[:n],
	)
	if err != nil {
		return fmt.Errorf(
			"invalid AUTH response: %w",
			err,
		)
	}

	// ============================================================
	// AUTH FAIL
	// ============================================================

	if header.Type == protocol.TypeAuthFail {

		return fmt.Errorf(
			"center rejected authentication: %s",
			string(payload),
		)
	}

	// ============================================================
	// AUTH OK
	// ============================================================

	if header.Type != protocol.TypeAuthOK {

		return fmt.Errorf(
			"unexpected AUTH response type: %d",
			header.Type,
		)
	}

	// AUTH_OK payload:
	//
	// 4 bytes:
	//
	//     VPN IPv4
	//

	if len(payload) != 4 {
		return fmt.Errorf(
			"invalid AUTH_OK payload length: %d",
			len(payload),
		)
	}

	// SessionID
	SessionID = header.SessionID

	// VPN IP
	ClientIP = net.IP(
		payload,
	).String()

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
	fmt.Println("VPN authentication successful")
	fmt.Println("==============================")
	fmt.Println(
		"SessionID:",
		SessionID,
	)
	fmt.Println(
		"VPN IP:",
		ClientIP,
	)
	fmt.Println(
		"Gateway IP:",
		GatewayIP,
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

		// ========================================================
		// 简单检查 IPv4
		// ========================================================

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
			"TUN -> UDP: %s -> %s, protocol=%d, len=%d, session=%d\n",
			srcIP,
			dstIP,
			packet[9],
			len(packet),
			SessionID,
		)

		// ========================================================
		// VTUN 封装
		// ========================================================

		vpnPacket := protocol.Pack(
			protocol.TypeIP,
			SessionID,
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

		// ========================================================
		// 检查类型
		// ========================================================

		if header.Type != protocol.TypeIP {

			fmt.Printf(
				"ignore packet type=%d\n",
				header.Type,
			)

			continue
		}

		// ========================================================
		// 检查 SessionID
		// ========================================================

		if header.SessionID != SessionID {

			fmt.Printf(
				"ignore packet: session=%d, expected=%d\n",
				header.SessionID,
				SessionID,
			)

			continue
		}

		// ========================================================
		// 检查 IP Packet
		// ========================================================

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
			"UDP -> TUN: %s -> %s, protocol=%d, len=%d, session=%d\n",
			srcIP,
			dstIP,
			packet[9],
			len(packet),
			header.SessionID,
		)

		// ========================================================
		// 写入 TUN
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
// 以下两个函数由各平台文件实现：
//
//     tun_darwin.go   - macOS（ifconfig / route）
//     tun_linux.go    - Linux（ip addr / ip route）
//     tun_windows.go  - Windows（netsh / route，依赖 TAP-Windows 驱动）
//
// configureTUN 配置 TUN 设备 IP：
//
//     configureTUN(tunName, clientIP, peerIP string) error
//
//     tunName:  TUN 设备名（macOS 为 utunX，Linux 为 tun0，Windows 为适配器名）
//     clientIP: Center 分配的 VPN IP
//     peerIP:   对端（Gateway TUN）地址，点对点平台使用
//
// configureRoute 配置公司网段路由：
//
//     configureRoute(network, gatewayIP string) error
//
//     network:   公司网段 CIDR，例如 192.168.0.0/24
//     gatewayIP: 下一跳（Gateway TUN 地址）
//
// ============================================================
