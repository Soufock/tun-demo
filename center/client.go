package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"tun-demo/protocol"
)

// ============================================================
// ClientSession
// ============================================================

type ClientSession struct {
	ID        uint32
	VPNIP     net.IP
	Addr      *net.UDPAddr
	GatewayID string
	LastSeen  time.Time
}

// ============================================================
// ClientManager
//
// 管理 Client Session 和 VPN IP 地址池，
// 内部持有三份索引：
//
//     byID   - SessionID -> Session
//     byIP   - VPN IP   -> Session
//     byAddr - "ip:port" -> Session（按来源地址 O(1) 匹配）
//
// ============================================================

type ClientManager struct {
	mu sync.RWMutex

	byID   map[uint32]*ClientSession
	byIP   map[string]*ClientSession
	byAddr map[string]*ClientSession

	// 已经分配的 VPN IP
	allocated map[string]bool

	nextSessionID uint32
}

func NewClientManager() *ClientManager {

	return &ClientManager{
		byID:      make(map[uint32]*ClientSession),
		byIP:      make(map[string]*ClientSession),
		byAddr:    make(map[string]*ClientSession),
		allocated: make(map[string]bool),

		nextSessionID: FirstSessionID,
	}
}

// ============================================================
// 认证 + 分配 Session
//
// SessionID / VPN IP 分配和注册到索引
// 在同一把锁内完成，保证原子性
// ============================================================

func (m *ClientManager) Authenticate(
	addr *net.UDPAddr,
) (*ClientSession, error) {

	m.mu.Lock()
	defer m.mu.Unlock()

	vpnIP := m.allocateVPNIP()

	if vpnIP == nil {
		return nil, fmt.Errorf(
			"no VPN IP available",
		)
	}

	sessionID := m.nextSessionID
	m.nextSessionID++

	session := &ClientSession{
		ID:       sessionID,
		VPNIP:    vpnIP,
		Addr:     addr,
		LastSeen: time.Now(),
	}

	m.byID[sessionID] = session
	m.byIP[vpnIP.String()] = session
	m.byAddr[addrKey(addr)] = session
	m.allocated[vpnIP.String()] = true

	return session, nil
}

// ============================================================
// 查找
// ============================================================

func (m *ClientManager) FindByID(
	id uint32,
) *ClientSession {

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.byID[id]
}

func (m *ClientManager) FindByIP(
	ip string,
) *ClientSession {

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.byIP[ip]
}

func (m *ClientManager) FindByAddr(
	addr *net.UDPAddr,
) *ClientSession {

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

func (m *ClientManager) UpdateAddr(
	session *ClientSession,
	addr *net.UDPAddr,
) {

	m.mu.Lock()
	defer m.mu.Unlock()

	if session.Addr != nil {
		delete(
			m.byAddr,
			addrKey(session.Addr),
		)
	}

	session.Addr = addr
	session.LastSeen = time.Now()

	m.byAddr[addrKey(addr)] = session
}

// ============================================================
// 分配 VPN IP
//
// 10.10.0.10 - 10.10.0.254，allocated map 去重
//
// 调用方必须持有 m.mu
// ============================================================

func (m *ClientManager) allocateVPNIP() net.IP {

	for i := VPNStart; i <= VPNEnd; i++ {

		ip := net.IPv4(
			10,
			10,
			0,
			byte(i),
		).To4()

		if !m.allocated[ip.String()] {
			return ip
		}
	}

	return nil
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
