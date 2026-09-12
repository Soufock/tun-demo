// Package relay 是 Center 的核心中转逻辑：
//
// UDP 主循环收包、按协议 Type 分发（Client 认证 / Gateway 认证 /
// IP 转发），并组合 client / gateway / route 三个 Manager
// 完成 Session 管理、Gateway 注册和路由查找。
//
// Center 不创建 TUN，只做 UDP 中继。
package relay

import (
	"fmt"
	"log"
	"net"
	"time"

	"tun-demo/center/client"
	"tun-demo/center/gateway"
	"tun-demo/center/route"
	"tun-demo/protocol"
)

// ============================================================
// 配置
//
// 由 main 传入，子包不反向依赖 main
// ============================================================

type Config struct {

	// 鉴权 Token
	AuthToken string

	// VPN IP 地址池：10.10.0.[VPNStart] - 10.10.0.[VPNEnd]
	VPNStart int
	VPNEnd   int

	// SessionID 起始值，之后递增
	FirstSessionID uint32
}

// ============================================================
// Center
//
// 只组合各 Manager：
//
//     ClientManager  - Client Session / VPN IP 地址池
//     GatewayManager - Gateway 注册
//     RouteTable     - 网段 -> Gateway 路由
//
// ============================================================

type Center struct {
	conn      *net.UDPConn
	authToken string

	clients  *client.ClientManager
	gateways *gateway.GatewayManager
	routes   *route.RouteTable
}

func NewCenter(
	conn *net.UDPConn,
	config Config,
) *Center {

	return &Center{
		conn:      conn,
		authToken: config.AuthToken,

		clients: client.NewClientManager(
			config.VPNStart,
			config.VPNEnd,
			config.FirstSessionID,
		),

		gateways: gateway.NewGatewayManager(),
		routes:   route.NewRouteTable(),
	}
}

// ============================================================
// 主循环
// ============================================================

func (c *Center) Serve() {

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
	if token != c.authToken {

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

	session, err := c.clients.Authenticate(addr)

	if err != nil {

		fmt.Printf(
			"client auth failed: addr=%s reason=%v\n",
			addr,
			err,
		)

		c.reply(
			addr,
			protocol.TypeAuthFail,
			0,
			[]byte(err.Error()),
		)

		return
	}

	fmt.Printf(
		"client authenticated: session=%d vpn_ip=%s addr=%s\n",
		session.ID,
		session.VPNIP,
		addr,
	)

	// ============================================================
	// AUTH_OK payload：4 字节 VPN IPv4
	// ============================================================

	c.reply(
		addr,
		protocol.TypeAuthOK,
		session.ID,
		session.VPNIP.To4(),
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

	if auth.Token != c.authToken {

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

	gw := &gateway.Gateway{
		ID:       auth.GatewayID,
		Addr:     addr,
		Networks: networks,
		LastSeen: time.Now(),
	}

	old := c.gateways.Register(gw)

	fmt.Printf(
		"gateway authenticated: id=%s addr=%s\n",
		gw.ID,
		addr,
	)

	// ============================================================
	// 重复注册：先删除旧路由，再建立新路由，避免重复
	// ============================================================

	if old != nil {
		c.routes.DeleteByGateway(gw.ID)
	}

	for _, ipNet := range networks {

		c.routes.Add(
			ipNet,
			gw.ID,
		)

		fmt.Printf(
			"route added: %s -> %s\n",
			ipNet,
			gw.ID,
		)
	}

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

	if gw := c.gateways.FindByAddr(addr); gw != nil {

		// 更新地址，适应 NAT 端口变化
		c.gateways.UpdateAddr(
			gw,
			addr,
		)

		session := c.clients.FindByIP(
			dstIP.String(),
		)

		if session == nil {

			log.Printf(
				"gateway -> client: no session for dst=%s gateway=%s\n",
				dstIP,
				gw.ID,
			)

			return
		}

		fmt.Printf(
			"gateway -> client: gateway=%s dst=%s session=%d\n",
			gw.ID,
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

	session := c.clients.FindByAddr(addr)

	if session == nil {

		log.Printf(
			"IP packet from unknown addr=%s session=%d\n",
			addr,
			header.SessionID,
		)

		return
	}

	// 校验 SessionID，防止伪造或串号
	if header.SessionID != session.ID {

		log.Printf(
			"session mismatch: addr=%s header=%d expected=%d\n",
			addr,
			header.SessionID,
			session.ID,
		)

		return
	}

	// 更新地址，适应 NAT 端口变化
	c.clients.UpdateAddr(
		session,
		addr,
	)

	gatewayID := c.routes.FindGatewayID(dstIP)

	if gatewayID == "" {

		log.Printf(
			"client -> gateway: no route for dst=%s session=%d\n",
			dstIP,
			session.ID,
		)

		return
	}

	gw := c.gateways.FindByID(gatewayID)

	if gw == nil {

		log.Printf(
			"client -> gateway: gateway=%s not found session=%d\n",
			gatewayID,
			session.ID,
		)

		return
	}

	fmt.Printf(
		"client -> gateway: session=%d dst=%s gateway=%s\n",
		session.ID,
		dstIP,
		gw.ID,
	)

	_, err := c.conn.WriteToUDP(
		rawPacket,
		gw.Addr,
	)
	if err != nil {
		log.Println("UDP send error:", err)
	}
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
