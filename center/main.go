package main

import (
	"fmt"
	"log"
	"net"
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

	center := NewCenter(conn)

	center.serve()
}
