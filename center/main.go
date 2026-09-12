package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"tun-demo/protocol"
)

const (

	// ============================================================
	// Center
	// ============================================================

	// UDP 监听地址（可按部署环境修改）
	ListenAddr = ":19000"

	// 鉴权 Token
	//
	// 现在先简单使用固定 Token。
	// 后面可以换成真正的用户 Token / JWT / API Key。
	AuthToken = "123456"

	// ============================================================
	// VPN
	// ============================================================

	// VPN IP 地址池：
	//
	//     10.10.0.10 - 10.10.0.254
	//
	VPNStart = 10
	VPNEnd   = 254

	// SessionID 从 10001 开始递增
	FirstSessionID = 10001
)

// ============================================================
// 数据结构
// ============================================================

type ClientSession struct {
	ID        uint32
	VPNIP     net.IP
	Addr      *net.UDPAddr
	GatewayID string
	LastSeen  time.Time
}

type Gateway struct {
	ID       string
	Addr     *net.UDPAddr
	Networks []*net.IPNet
	LastSeen time.Time
}

type Route struct {
	Network   *net.IPNet
	GatewayID string
}

type Center struct {
	conn *net.UDPConn

	clientsMu   sync.RWMutex
	clients     map[uint32]*ClientSession
	clientsByIP map[string]*ClientSession

	// 已经分配的 VPN IP
	allocated map[string]bool

	gatewaysMu sync.RWMutex
	gateways   map[string]*Gateway

	routesMu sync.RWMutex
	routes   []Route

	nextSessionID uint32
}

func main() {

	// ============================================================
	// UDP Server
	//
	// Center 不创建 TUN，只做 UDP 中继
	// ============================================================

	addr, err := net.ResolveUDPAddr(
		"udp",
		ListenAddr,
	)
	if err != nil {
		log.Fatal("resolve listen addr:", err)
	}

	conn, err := net.ListenUDP(
		"udp",
		addr,
	)
	if err != nil {
		log.Fatal("listen udp:", err)
	}

	defer conn.Close()

	fmt.Println("Center UDP listen:", addr)

	center := &Center{
		conn: conn,

		clients:     make(map[uint32]*ClientSession),
		clientsByIP: make(map[string]*ClientSession),
		allocated:   make(map[string]bool),

		gateways: make(map[string]*Gateway),

		nextSessionID: FirstSessionID,
	}

	center.serve()
}

// ============================================================
// 主循环
// ============================================================

func (c *Center) serve() {

	buf := make(
		[]byte,
		protocol.MaxPacket+protocol.HeaderSize,
	)

	for {

		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP read error:", err)
			continue
		}

		header, payload, err := protocol.Unpack(
			buf[:n],
		)
		if err != nil {
			log.Println(
				"invalid VPN packet from",
				addr,
				":",
				err,
			)
			continue
		}

		switch header.Type {

		case protocol.TypeAuth:

			c.handleClientAuth(
				addr,
				payload,
			)

		case protocol.TypeGatewayAuth:

			c.handleGatewayAuth(
				addr,
				payload,
			)

		case protocol.TypeIP:

			c.handleIP(
				addr,
				header,
				buf[:n],
				payload,
			)

		default:

			log.Println(
				"unsupported packet type:",
				header.Type,
			)
		}
	}
}

// ============================================================
// Client AUTH
//
// 校验 Token，分配 SessionID 和 VPN IP
// ============================================================

func (c *Center) handleClientAuth(
	addr *net.UDPAddr,
	payload []byte,
) {

	token := string(payload)

	// 简单鉴权
	if token != AuthToken {

		fmt.Printf(
			"client auth failed: addr=%s\n",
			addr,
		)

		c.reply(
			addr,
			protocol.TypeAuthFail,
			0,
			[]byte("invalid token"),
		)

		return
	}

	// ============================================================
	// 分配 Session 和 VPN IP
	// ============================================================

	c.clientsMu.Lock()

	vpnIP := c.allocateVPNIP()

	if vpnIP == nil {
		c.clientsMu.Unlock()

		fmt.Printf(
			"client auth failed: addr=%s reason=no VPN IP available\n",
			addr,
		)

		c.reply(
			addr,
			protocol.TypeAuthFail,
			0,
			[]byte("no VPN IP available"),
		)

		return
	}

	sessionID := c.nextSessionID
	c.nextSessionID++

	session := &ClientSession{
		ID:       sessionID,
		VPNIP:    vpnIP,
		Addr:     addr,
		LastSeen: time.Now(),
	}

	c.clients[sessionID] = session
	c.clientsByIP[vpnIP.String()] = session
	c.allocated[vpnIP.String()] = true

	c.clientsMu.Unlock()

	fmt.Printf(
		"client authenticated: session=%d vpn_ip=%s addr=%s\n",
		sessionID,
		vpnIP,
		addr,
	)

	// ============================================================
	// AUTH_OK payload：4 字节 VPN IPv4
	// ============================================================

	c.reply(
		addr,
		protocol.TypeAuthOK,
		sessionID,
		vpnIP.To4(),
	)
}

// ============================================================
// Gateway AUTH
//
// 校验 Token，保存 Gateway，并为每个 network 自动建立路由
// ============================================================

func (c *Center) handleGatewayAuth(
	addr *net.UDPAddr,
	payload []byte,
) {

	auth, err := protocol.UnmarshalGatewayAuth(payload)
	if err != nil {

		fmt.Printf(
			"gateway auth failed: addr=%s reason=%v\n",
			addr,
			err,
		)

		c.reply(
			addr,
			protocol.TypeGatewayAuthFail,
			0,
			[]byte("invalid gateway auth"),
		)

		return
	}

	if auth.Token != AuthToken {

		fmt.Printf(
			"gateway auth failed: addr=%s id=%s reason=invalid token\n",
			addr,
			auth.GatewayID,
		)

		c.reply(
			addr,
			protocol.TypeGatewayAuthFail,
			0,
			[]byte("invalid token"),
		)

		return
	}

	// ============================================================
	// 解析内网网段
	// ============================================================

	var networks []*net.IPNet

	for _, s := range auth.Networks {

		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {

			fmt.Printf(
				"gateway auth failed: addr=%s id=%s reason=invalid network %q\n",
				addr,
				auth.GatewayID,
				s,
			)

			c.reply(
				addr,
				protocol.TypeGatewayAuthFail,
				0,
				[]byte("invalid network: "+s),
			)

			return
		}

		networks = append(
			networks,
			ipNet,
		)
	}

	// ============================================================
	// 保存 Gateway
	// ============================================================

	gateway := &Gateway{
		ID:       auth.GatewayID,
		Addr:     addr,
		Networks: networks,
		LastSeen: time.Now(),
	}

	c.gatewaysMu.Lock()
	c.gateways[gateway.ID] = gateway
	c.gatewaysMu.Unlock()

	fmt.Printf(
		"gateway authenticated: id=%s addr=%s\n",
		gateway.ID,
		addr,
	)

	// ============================================================
	// 自动建立路由
	// ============================================================

	c.routesMu.Lock()

	for _, ipNet := range networks {

		c.routes = append(
			c.routes,
			Route{
				Network:   ipNet,
				GatewayID: gateway.ID,
			},
		)

		fmt.Printf(
			"route added: %s -> %s\n",
			ipNet,
			gateway.ID,
		)
	}

	c.routesMu.Unlock()

	c.reply(
		addr,
		protocol.TypeGatewayAuthOK,
		0,
		nil,
	)
}

// ============================================================
// IP 转发
//
// 来源是 Client：
//
//     目的 IP -> 路由 -> Gateway
//
// 来源是 Gateway：
//
//     目的 VPN IP -> Client Session
//
// 来源通过 addr 匹配已知 gateway / session 区分
// ============================================================

func (c *Center) handleIP(
	addr *net.UDPAddr,
	header *protocol.Header,
	rawPacket []byte,
	ipPacket []byte,
) {

	if len(ipPacket) < 20 {
		log.Println(
			"IP packet too small from",
			addr,
		)
		return
	}

	dstIP := net.IP(
		ipPacket[16:20],
	)

	// ============================================================
	// Gateway -> Client
	// ============================================================

	if gateway := c.findGatewayByAddr(addr); gateway != nil {

		// 更新地址，适应 NAT 端口变化
		c.gatewaysMu.Lock()
		gateway.Addr = addr
		gateway.LastSeen = time.Now()
		c.gatewaysMu.Unlock()

		c.clientsMu.RLock()
		session := c.clientsByIP[dstIP.String()]
		c.clientsMu.RUnlock()

		if session == nil {

			log.Printf(
				"gateway -> client: no session for dst=%s gateway=%s\n",
				dstIP,
				gateway.ID,
			)

			return
		}

		fmt.Printf(
			"gateway -> client: gateway=%s dst=%s session=%d\n",
			gateway.ID,
			dstIP,
			session.ID,
		)

		_, err := c.conn.WriteToUDP(
			rawPacket,
			session.Addr,
		)
		if err != nil {
			log.Println("UDP send error:", err)
		}

		return
	}

	// ============================================================
	// Client -> Gateway
	// ============================================================

	session := c.findClientByAddr(addr)

	if session == nil {

		log.Printf(
			"IP packet from unknown addr=%s session=%d\n",
			addr,
			header.SessionID,
		)

		return
	}

	// 更新地址，适应 NAT 端口变化
	c.clientsMu.Lock()
	session.Addr = addr
	session.LastSeen = time.Now()
	c.clientsMu.Unlock()

	gateway := c.routeGateway(dstIP)

	if gateway == nil {

		log.Printf(
			"client -> gateway: no route for dst=%s session=%d\n",
			dstIP,
			session.ID,
		)

		return
	}

	fmt.Printf(
		"client -> gateway: session=%d dst=%s gateway=%s\n",
		session.ID,
		dstIP,
		gateway.ID,
	)

	_, err := c.conn.WriteToUDP(
		rawPacket,
		gateway.Addr,
	)
	if err != nil {
		log.Println("UDP send error:", err)
	}
}

// ============================================================
// 路由查找：目的 IP -> Gateway
// ============================================================

func (c *Center) routeGateway(
	dstIP net.IP,
) *Gateway {

	c.routesMu.RLock()

	var gatewayID string

	for _, route := range c.routes {
		if route.Network.Contains(dstIP) {
			gatewayID = route.GatewayID
			break
		}
	}

	c.routesMu.RUnlock()

	if gatewayID == "" {
		return nil
	}

	c.gatewaysMu.RLock()
	gateway := c.gateways[gatewayID]
	c.gatewaysMu.RUnlock()

	return gateway
}

// ============================================================
// 按 UDP 地址匹配来源
// ============================================================

func (c *Center) findGatewayByAddr(
	addr *net.UDPAddr,
) *Gateway {

	c.gatewaysMu.RLock()
	defer c.gatewaysMu.RUnlock()

	for _, gateway := range c.gateways {
		if sameUDPAddr(gateway.Addr, addr) {
			return gateway
		}
	}

	return nil
}

func (c *Center) findClientByAddr(
	addr *net.UDPAddr,
) *ClientSession {

	c.clientsMu.RLock()
	defer c.clientsMu.RUnlock()

	for _, session := range c.clients {
		if sameUDPAddr(session.Addr, addr) {
			return session
		}
	}

	return nil
}

func sameUDPAddr(
	a *net.UDPAddr,
	b *net.UDPAddr,
) bool {

	return a != nil &&
		b != nil &&
		a.Port == b.Port &&
		a.IP.Equal(b.IP)
}

// ============================================================
// 分配 VPN IP
//
// 10.10.0.10 - 10.10.0.254，allocated map 去重
// ============================================================

func (c *Center) allocateVPNIP() net.IP {

	for i := VPNStart; i <= VPNEnd; i++ {

		ip := net.IPv4(
			10,
			10,
			0,
			byte(i),
		).To4()

		if !c.allocated[ip.String()] {
			return ip
		}
	}

	return nil
}

// ============================================================
// 回复
// ============================================================

func (c *Center) reply(
	addr *net.UDPAddr,
	packetType uint8,
	sessionID uint32,
	payload []byte,
) {

	packet := protocol.Pack(
		packetType,
		sessionID,
		0,
		payload,
	)

	_, err := c.conn.WriteToUDP(
		packet,
		addr,
	)
	if err != nil {
		log.Println(
			"UDP send error:",
			err,
		)
	}
}
