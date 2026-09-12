package main

import (
	"log"
	"net"
	"strconv"

	"tun-demo/protocol"
)

// ============================================================
// Center
//
// 只组合各 Manager：
//
//     ClientManager  - Client Session / VPN IP 地址池
//     GatewayManager - Gateway 注册
//     RouteTable     - 网段 -> Gateway 路由
//
// Center 自身不直接持有 mutex 和 map
// ============================================================

type Center struct {
	conn *net.UDPConn

	clients  *ClientManager
	gateways *GatewayManager
	routes   *RouteTable
}

func NewCenter(conn *net.UDPConn) *Center {

	return &Center{
		conn: conn,

		clients:  NewClientManager(),
		gateways: NewGatewayManager(),
		routes:   NewRouteTable(),
	}
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

// ============================================================
// UDP 地址索引 key："ip:port"
// ============================================================

func addrKey(addr *net.UDPAddr) string {

	return net.JoinHostPort(
		addr.IP.String(),
		strconv.Itoa(addr.Port),
	)
}
