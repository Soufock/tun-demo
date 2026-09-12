package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/songgao/water"
)

const (

	// ============================================================
	// VPN 协议
	// ============================================================

	Magic      = "VTUN"
	Version    = 1
	HeaderSize = 16
	MaxPacket  = 65535

	// Packet Type
	TypeAuth     = 1
	TypeAuthOK   = 2
	TypeAuthFail = 3
	TypeIP       = 4

	// ============================================================
	// Server
	// ============================================================

	ServerAddr = "103.217.197.174:19000"

	// 鉴权 Token
	//
	// 现在先简单使用固定 Token。
	// 后面可以换成真正的用户 Token / JWT / API Key。
	AuthToken = "123456"

	// ============================================================
	// VPN
	// ============================================================

	// VPN Server 的虚拟地址
	//
	// Server:
	//     10.10.0.2
	//
	// Client:
	//     由 Server 动态分配
	//
	ServerIP = "10.10.0.2"

	// 需要通过 VPN 访问的公司网段
	//
	// 例如：
	//
	// 10.88.0.0/24
	//
	VPNNetwork = "10.88.0.0/24"
)

// ============================================================
// 动态获取的 Session 信息
// ============================================================

var (
	// Server 分配
	SessionID uint32

	// Server 分配
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
	// 2. 连接 VPN Server
	// ============================================================

	serverAddr, err := net.ResolveUDPAddr(
		"udp",
		ServerAddr,
	)
	if err != nil {
		log.Fatal("resolve server:", err)
	}

	conn, err := net.DialUDP(
		"udp",
		nil,
		serverAddr,
	)
	if err != nil {
		log.Fatal("connect server:", err)
	}

	defer conn.Close()

	fmt.Println(
		"UDP server:",
		serverAddr,
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
		ServerIP,
	); err != nil {
		log.Fatal(err)
	}

	// ============================================================
	// 5. 自动配置 VPN 路由
	// ============================================================

	if err := configureRoute(
		VPNNetwork,
		ServerIP,
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
// ============================================================
//
// Client:
//
//     AUTH + Token
//
// Server:
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

	authPacket := pack(
		TypeAuth,
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

	header, payload, err := unpack(
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

	if header.Type == TypeAuthFail {

		return fmt.Errorf(
			"server rejected authentication: %s",
			string(payload),
		)
	}

	// ============================================================
	// AUTH OK
	// ============================================================

	if header.Type != TypeAuthOK {

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
		"Server IP:",
		ServerIP,
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
		MaxPacket,
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

		vpnPacket := pack(
			TypeIP,
			SessionID,
			0,
			packet,
		)

		// ========================================================
		// UDP 发送
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
		MaxPacket+HeaderSize,
	)

	for {

		// ========================================================
		// UDP 接收
		// ========================================================

		n, addr, err := conn.ReadFromUDP(
			buf,
		)
		if err != nil {
			log.Println(
				"UDP read error:",
				err,
			)
			continue
		}

		fmt.Printf(
			"UDP <- %s: %d bytes\n",
			addr,
			n,
		)

		// ========================================================
		// 解包
		// ========================================================

		header, packet, err := unpack(
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

		if header.Type != TypeIP {

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
// 配置 TUN
// ============================================================

func configureTUN(
	tunName string,
	clientIP string,
	serverIP string,
) error {

	fmt.Printf(
		"Configuring TUN %s...\n",
		tunName,
	)

	// ============================================================
	// macOS
	//
	// ifconfig utun4 10.10.0.10 10.10.0.2
	// ============================================================

	cmd := exec.Command(
		"ifconfig",
		tunName,
		clientIP,
		serverIP,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {

		return fmt.Errorf(
			"configure TUN failed: %v: %s",
			err,
			strings.TrimSpace(
				string(output),
			),
		)
	}

	fmt.Printf(
		"TUN configured: %s -> %s -> %s\n",
		tunName,
		clientIP,
		serverIP,
	)

	return nil
}

// ============================================================
// 配置路由
// ============================================================

func configureRoute(
	vpnNetwork string,
	serverIP string,
) error {

	fmt.Printf(
		"Configuring route %s via %s...\n",
		vpnNetwork,
		serverIP,
	)

	// ============================================================
	// macOS
	//
	// 先删除旧路由
	//
	// route delete -net 10.88.0.0/24
	// ============================================================

	fmt.Println(
		"Deleting old route if exists...",
	)

	delCmd := exec.Command(
		"route",
		"delete",
		"-net",
		vpnNetwork,
	)

	output, err := delCmd.CombinedOutput()

	if err != nil {

		// 路由不存在属于正常情况
		fmt.Printf(
			"Delete route result: %s\n",
			strings.TrimSpace(
				string(output),
			),
		)
	} else {

		fmt.Println(
			"Old route deleted.",
		)
	}

	// ============================================================
	// 添加新路由
	//
	// route add -net 10.88.0.0/24 10.10.0.2
	// ============================================================

	cmd := exec.Command(
		"route",
		"add",
		"-net",
		vpnNetwork,
		serverIP,
	)

	output, err = cmd.CombinedOutput()

	if err != nil {

		// 已经存在也可以忽略
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
			strings.TrimSpace(
				string(output),
			),
		)
	}

	fmt.Printf(
		"Route added: %s -> %s\n",
		vpnNetwork,
		serverIP,
	)

	return nil
}

// ============================================================
// Pack
//
// Header:
//
// 0       4   5   6       8       12      16
// +-------+---+---+-------+-------+-------+
// | Magic | V | T | Len   | Sess  | Seq   |
// +-------+---+---+-------+-------+-------+
// |              Payload                |
// +-------------------------------------+
// ============================================================

func pack(
	packetType uint8,
	sessionID uint32,
	sequence uint32,
	payload []byte,
) []byte {

	if len(payload) > 65535 {
		panic("payload too large")
	}

	vpnPacket := make(
		[]byte,
		HeaderSize+len(payload),
	)

	// Magic
	copy(
		vpnPacket[0:4],
		Magic,
	)

	// Version
	vpnPacket[4] = Version

	// Type
	vpnPacket[5] = packetType

	// Payload length
	binary.BigEndian.PutUint16(
		vpnPacket[6:8],
		uint16(len(payload)),
	)

	// SessionID
	binary.BigEndian.PutUint32(
		vpnPacket[8:12],
		sessionID,
	)

	// Sequence
	binary.BigEndian.PutUint32(
		vpnPacket[12:16],
		sequence,
	)

	// Payload
	copy(
		vpnPacket[HeaderSize:],
		payload,
	)

	return vpnPacket
}

// ============================================================
// Unpack
// ============================================================

func unpack(
	data []byte,
) (
	*Header,
	[]byte,
	error,
) {

	if len(data) < HeaderSize {

		return nil, nil, fmt.Errorf(
			"packet too short: %d",
			len(data),
		)
	}

	// ============================================================
	// Magic
	// ============================================================

	if string(data[0:4]) != Magic {

		return nil, nil, fmt.Errorf(
			"invalid magic: %q",
			string(data[0:4]),
		)
	}

	// ============================================================
	// Version
	// ============================================================

	if data[4] != Version {

		return nil, nil, fmt.Errorf(
			"invalid version: %d",
			data[4],
		)
	}

	// ============================================================
	// Header
	// ============================================================

	header := &Header{
		Version: data[4],
		Type:    data[5],

		Length: binary.BigEndian.Uint16(
			data[6:8],
		),

		SessionID: binary.BigEndian.Uint32(
			data[8:12],
		),

		Sequence: binary.BigEndian.Uint32(
			data[12:16],
		),
	}

	// ============================================================
	// Payload length
	// ============================================================

	payloadLen := int(
		header.Length,
	)

	if payloadLen <= 0 {

		return nil, nil, fmt.Errorf(
			"invalid payload length: %d",
			payloadLen,
		)
	}

	if HeaderSize+payloadLen > len(data) {

		return nil, nil, fmt.Errorf(
			"invalid packet length: header=%d payload=%d udp=%d",
			HeaderSize,
			payloadLen,
			len(data),
		)
	}

	// ============================================================
	// Payload
	// ============================================================

	payload := data[HeaderSize : HeaderSize+payloadLen]

	return header, payload, nil
}

// ============================================================
// Header
// ============================================================

type Header struct {
	Version   uint8
	Type      uint8
	Length    uint16
	SessionID uint32
	Sequence  uint32
}
