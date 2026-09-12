package main

import (
	"fmt"
	"log"
	"net"

	"tun-demo/protocol"
)

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

	if gateway := c.gateways.FindByAddr(addr); gateway != nil {

		// 更新地址，适应 NAT 端口变化
		c.gateways.UpdateAddr(
			gateway,
			addr,
		)

		session := c.clients.FindByIP(
			dstIP.String(),
		)

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

	gateway := c.gateways.FindByID(gatewayID)

	if gateway == nil {

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
