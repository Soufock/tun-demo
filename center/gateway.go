package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"tun-demo/protocol"
)

// ============================================================
// Gateway
// ============================================================

type Gateway struct {
	ID       string
	Addr     *net.UDPAddr
	Networks []*net.IPNet
	LastSeen time.Time
}

// ============================================================
// GatewayManager
//
// 管理已注册的 Gateway，
// 内部持有两份索引：
//
//     byID   - GatewayID  -> Gateway
//     byAddr - "ip:port"  -> Gateway（按来源地址 O(1) 匹配）
//
// ============================================================

type GatewayManager struct {
	mu sync.RWMutex

	byID   map[string]*Gateway
	byAddr map[string]*Gateway
}

func NewGatewayManager() *GatewayManager {

	return &GatewayManager{
		byID:   make(map[string]*Gateway),
		byAddr: make(map[string]*Gateway),
	}
}

// ============================================================
// 注册
//
// 返回被替换掉的旧 Gateway（同 ID 重复注册时），
// 调用方据此清理旧路由
// ============================================================

func (m *GatewayManager) Register(
	gateway *Gateway,
) *Gateway {

	m.mu.Lock()
	defer m.mu.Unlock()

	old := m.byID[gateway.ID]

	if old != nil && old.Addr != nil {
		delete(
			m.byAddr,
			addrKey(old.Addr),
		)
	}

	m.byID[gateway.ID] = gateway
	m.byAddr[addrKey(gateway.Addr)] = gateway

	return old
}

// ============================================================
// 查找
// ============================================================

func (m *GatewayManager) FindByID(
	id string,
) *Gateway {

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.byID[id]
}

func (m *GatewayManager) FindByAddr(
	addr *net.UDPAddr,
) *Gateway {

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.byAddr[addrKey(addr)]
}

// ============================================================
// 更新 UDP 地址
//
// 适应 NAT 端口变化，
// byAddr 索引同步维护：删旧 key，写新 key
// ============================================================

func (m *GatewayManager) UpdateAddr(
	gateway *Gateway,
	addr *net.UDPAddr,
) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if gateway.Addr != nil {
		delete(
			m.byAddr,
			addrKey(gateway.Addr),
		)
	}

	gateway.Addr = addr
	gateway.LastSeen = time.Now()

	m.byAddr[addrKey(addr)] = gateway
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

	old := c.gateways.Register(gateway)

	fmt.Printf(
		"gateway authenticated: id=%s addr=%s\n",
		gateway.ID,
		addr,
	)

	// ============================================================
	// 重复注册：先删除旧路由，再建立新路由，避免重复
	// ============================================================

	if old != nil {
		c.routes.DeleteByGateway(gateway.ID)
	}

	for _, ipNet := range networks {

		c.routes.Add(
			ipNet,
			gateway.ID,
		)

		fmt.Printf(
			"route added: %s -> %s\n",
			ipNet,
			gateway.ID,
		)
	}

	c.reply(
		addr,
		protocol.TypeGatewayAuthOK,
		0,
		nil,
	)
}
