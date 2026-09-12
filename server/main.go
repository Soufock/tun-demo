package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
)

const (
	Magic      = "VTUN"
	Version    = 1
	HeaderSize = 16
	MaxPacket  = 65535

	TypeAuth     = 1
	TypeAuthOK   = 2
	TypeAuthFail = 3
	TypeIP       = 4

	// Server TUN
	TUNIP   = "10.10.0.2"
	TUNMask = "24"

	// VPN IP 地址池
	VPNNetwork = "10.10.0.0/24"
	VPNStart   = 10
	VPNEnd     = 254

	// 简单鉴权 token
	// 后面可以替换成真正的 JWT / API Key / 用户系统
	AuthToken = "123456"

	// UDP
	ListenAddr = ":19000"
)

// ============================================================
// Header
// ============================================================

type Header struct {
	Magic     [4]byte
	Version   uint8
	Type      uint8
	Length    uint16
	SessionID uint32
	Sequence  uint32
}

// ============================================================
// Session
// ============================================================

type Session struct {
	ID       uint32
	VPNIP    net.IP
	Client   *net.UDPAddr
	LastSeen time.Time
}

// ============================================================
// Server
// ============================================================

type VPNServer struct {
	tun  *water.Interface
	conn *net.UDPConn

	mu sync.RWMutex

	// SessionID -> Session
	sessions map[uint32]*Session

	// VPN IP -> Session
	sessionsByIP map[string]*Session

	// 已经分配的 VPN IP
	allocated map[string]bool

	nextSessionID uint32
}

func main() {
	// ========================================================
	// 1. 创建 TUN
	// ========================================================

	config := water.Config{
		DeviceType: water.TUN,
	}

	tun, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()

	fmt.Println("TUN:", tun.Name())

	// ========================================================
	// 2. 配置 TUN
	// ========================================================

	if err := configureTUN(tun.Name()); err != nil {
		log.Fatal(err)
	}

	// ========================================================
	// 3. UDP
	// ========================================================

	addr, err := net.ResolveUDPAddr("udp", ListenAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("UDP listen:", addr)

	server := &VPNServer{
		tun:  tun,
		conn: conn,

		sessions:     make(map[uint32]*Session),
		sessionsByIP: make(map[string]*Session),
		allocated:    make(map[string]bool),

		nextSessionID: 10000,
	}

	// ========================================================
	// 4. TUN -> UDP
	// ========================================================

	go server.tunToUDP()

	// ========================================================
	// 5. UDP -> TUN
	// ========================================================

	server.udpToTun()
}

// ============================================================
// TUN -> UDP
// ============================================================

func (s *VPNServer) tunToUDP() {
	buf := make([]byte, MaxPacket)

	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			log.Println("TUN read error:", err)
			continue
		}

		packet := append([]byte(nil), buf[:n]...)

		if len(packet) < 20 {
			log.Println("TUN packet too small")
			continue
		}

		// IPv4 dst
		dstIP := net.IP(packet[16:20]).String()

		s.mu.RLock()
		session := s.sessionsByIP[dstIP]
		s.mu.RUnlock()

		if session == nil {
			log.Println("TUN -> UDP: no session for", dstIP)
			continue
		}

		vpnPacket := pack(
			TypeIP,
			session.ID,
			0,
			packet,
		)

		_, err = s.conn.WriteToUDP(
			vpnPacket,
			session.Client,
		)
		if err != nil {
			log.Println("UDP send error:", err)
			continue
		}

		fmt.Printf(
			"TUN -> UDP: %s -> %s session=%d client=%s\n",
			net.IP(packet[12:16]),
			net.IP(packet[16:20]),
			session.ID,
			session.Client,
		)
	}
}

// ============================================================
// UDP -> TUN
// ============================================================

func (s *VPNServer) udpToTun() {
	buf := make([]byte, MaxPacket+HeaderSize)

	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP read error:", err)
			continue
		}

		header, payload, err := unpack(buf[:n])
		if err != nil {
			log.Println("invalid VPN packet:", err)
			continue
		}

		switch header.Type {

		case TypeAuth:

			s.handleAuth(addr, header, payload)

		case TypeIP:

			s.handleIP(addr, header, payload)

		default:

			log.Println("unsupported packet type:", header.Type)
		}
	}
}

// ============================================================
// AUTH
// ============================================================

func (s *VPNServer) handleAuth(
	addr *net.UDPAddr,
	header *Header,
	payload []byte,
) {
	token := string(payload)

	fmt.Printf(
		"AUTH <- %s token=%s\n",
		addr,
		token,
	)

	// 简单鉴权
	if token != AuthToken {

		fmt.Println("AUTH failed:", addr)

		response := pack(
			TypeAuthFail,
			0,
			0,
			[]byte("invalid token"),
		)

		_, err := s.conn.WriteToUDP(
			response,
			addr,
		)
		if err != nil {
			log.Println("AUTH_FAIL send error:", err)
		}

		return
	}

	// ========================================================
	// 分配 Session
	// ========================================================

	s.mu.Lock()

	sessionID := s.nextSessionID
	s.nextSessionID++

	vpnIP := s.allocateVPNIP()

	if vpnIP == nil {
		s.mu.Unlock()

		response := pack(
			TypeAuthFail,
			0,
			0,
			[]byte("no VPN IP available"),
		)

		_, _ = s.conn.WriteToUDP(
			response,
			addr,
		)

		return
	}

	session := &Session{
		ID:       sessionID,
		VPNIP:    vpnIP,
		Client:   addr,
		LastSeen: time.Now(),
	}

	s.sessions[sessionID] = session
	s.sessionsByIP[vpnIP.String()] = session
	s.allocated[vpnIP.String()] = true

	s.mu.Unlock()

	fmt.Printf(
		"AUTH OK: client=%s session=%d vpnIP=%s\n",
		addr,
		sessionID,
		vpnIP,
	)

	// ========================================================
	// AUTH_OK payload
	//
	// 4 bytes VPN IP
	// ========================================================

	payload = make([]byte, 4)
	copy(payload, vpnIP.To4())

	response := pack(
		TypeAuthOK,
		sessionID,
		0,
		payload,
	)

	_, err := s.conn.WriteToUDP(
		response,
		addr,
	)
	if err != nil {
		log.Println("AUTH_OK send error:", err)
	}
}

// ============================================================
// IP 数据包
// ============================================================

func (s *VPNServer) handleIP(
	addr *net.UDPAddr,
	header *Header,
	packet []byte,
) {
	s.mu.Lock()

	session := s.sessions[header.SessionID]

	if session == nil {
		s.mu.Unlock()

		log.Printf(
			"unknown session=%d from=%s\n",
			header.SessionID,
			addr,
		)

		return
	}

	// 更新 UDP 地址
	//
	// 这样客户端 UDP 源端口变化也可以继续使用
	session.Client = addr
	session.LastSeen = time.Now()

	s.mu.Unlock()

	if len(packet) < 20 {
		log.Println("IP packet too small")
		return
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	fmt.Printf(
		"UDP -> TUN: session=%d %s -> %s\n",
		header.SessionID,
		srcIP,
		dstIP,
	)

	_, err := s.tun.Write(packet)
	if err != nil {
		log.Println("TUN write error:", err)
	}
}

// ============================================================
// 分配 VPN IP
// ============================================================

func (s *VPNServer) allocateVPNIP() net.IP {
	for i := VPNStart; i <= VPNEnd; i++ {

		ip := net.IPv4(
			10,
			10,
			0,
			byte(i),
		).To4()

		key := ip.String()

		if !s.allocated[key] {
			return ip
		}
	}

	return nil
}

// ============================================================
// TUN 配置
// ============================================================

func configureTUN(name string) error {

	// 删除旧配置
	_ = exec.Command(
		"ip",
		"addr",
		"flush",
		"dev",
		name,
	).Run()

	// 10.10.0.2/24
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

	// UP
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
		"TUN configured: %s/%s\n",
		TUNIP,
		TUNMask,
	)

	return nil
}

// ============================================================
// Pack
// ============================================================

func pack(
	packetType uint8,
	sessionID uint32,
	sequence uint32,
	payload []byte,
) []byte {

	data := make([]byte, HeaderSize+len(payload))

	copy(
		data[0:4],
		Magic,
	)

	data[4] = Version
	data[5] = packetType

	binary.BigEndian.PutUint16(
		data[6:8],
		uint16(len(payload)),
	)

	binary.BigEndian.PutUint32(
		data[8:12],
		sessionID,
	)

	binary.BigEndian.PutUint32(
		data[12:16],
		sequence,
	)

	copy(
		data[HeaderSize:],
		payload,
	)

	return data
}

// ============================================================
// Unpack
// ============================================================

func unpack(data []byte) (
	*Header,
	[]byte,
	error,
) {

	if len(data) < HeaderSize {
		return nil, nil, fmt.Errorf(
			"packet too short",
		)
	}

	if string(data[0:4]) != Magic {
		return nil, nil, fmt.Errorf(
			"invalid magic",
		)
	}

	if data[4] != Version {
		return nil, nil, fmt.Errorf(
			"invalid version",
		)
	}

	header := &Header{
		Version:   data[4],
		Type:      data[5],
		Length:    binary.BigEndian.Uint16(data[6:8]),
		SessionID: binary.BigEndian.Uint32(data[8:12]),
		Sequence:  binary.BigEndian.Uint32(data[12:16]),
	}

	length := int(header.Length)

	if len(data) < HeaderSize+length {
		return nil, nil, fmt.Errorf(
			"invalid length: packet=%d payload=%d",
			len(data),
			length,
		)
	}

	payload := data[HeaderSize : HeaderSize+length]

	return header, payload, nil
}
