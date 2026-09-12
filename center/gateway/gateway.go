// Package gateway 负责 Center 侧 Gateway 的注册管理：
//
// 注册（同 ID 重复注册时返回旧实例以便清理旧路由）、
// 按 ID / UDP 来源地址双索引查找，
// 以及 NAT 端口变化时的地址更新。
//
// 纯数据管理，不做网络收发。
package gateway

import (
	"net"
	"strconv"
	"sync"
	"time"
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
// UDP 地址索引 key："ip:port"
// ============================================================

func addrKey(addr *net.UDPAddr) string {

	return net.JoinHostPort(
		addr.IP.String(),
		strconv.Itoa(addr.Port),
	)
}
