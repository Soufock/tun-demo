// Package client 负责 Center 侧 Client Session 的生命周期管理：
//
// 认证后的 Session 注册、SessionID / VPN IP 分配（地址池去重）、
// 按 ID / VPN IP / UDP 来源地址三种索引的查找，
// 以及 NAT 端口变化时的地址更新。
//
// 纯数据管理，不做网络收发。
package client

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
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
//     byID   - SessionID  -> Session
//     byIP   - VPN IP     -> Session
//     byAddr - "ip:port"  -> Session（按来源地址 O(1) 匹配）
//
// ============================================================

type ClientManager struct {
	mu sync.RWMutex

	byID   map[uint32]*ClientSession
	byIP   map[string]*ClientSession
	byAddr map[string]*ClientSession

	// 已经分配的 VPN IP
	allocated map[string]bool

	// VPN IP 地址池范围：10.10.0.[vpnStart] - 10.10.0.[vpnEnd]
	vpnStart int
	vpnEnd   int

	nextSessionID uint32
}

func NewClientManager(
	vpnStart int,
	vpnEnd int,
	firstSessionID uint32,
) *ClientManager {

	return &ClientManager{
		byID:      make(map[uint32]*ClientSession),
		byIP:      make(map[string]*ClientSession),
		byAddr:    make(map[string]*ClientSession),
		allocated: make(map[string]bool),

		vpnStart: vpnStart,
		vpnEnd:   vpnEnd,

		nextSessionID: firstSessionID,
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
// 10.10.0.[vpnStart] - 10.10.0.[vpnEnd]，allocated map 去重
//
// 调用方必须持有 m.mu
// ============================================================

func (m *ClientManager) allocateVPNIP() net.IP {

	for i := m.vpnStart; i <= m.vpnEnd; i++ {

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
// UDP 地址索引 key："ip:port"
// ============================================================

func addrKey(addr *net.UDPAddr) string {

	return net.JoinHostPort(
		addr.IP.String(),
		strconv.Itoa(addr.Port),
	)
}
